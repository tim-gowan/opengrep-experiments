from nt import system
from langchain_ollama import ChatOllama
from tenacity import retry, stop_after_attempt, wait_fixed
import subprocess
import platform
import sys
import re

class BenchmarkTest00007:
    def __init__(self):      
        self.system_prompt = f"You are a helpful IT assistant that listens to an administrative channel and responds ONLY in {self.get_shell()} commands."
    def __set_system_prompt(self, system_prompt: str):
        self.system_prompt = system_prompt
    def initialize_ollama(self, model = "gemma3:27b"):
        ## Must install ollama first: https://ollama.com/
        # Then start the ollama server: ollama serve    
        # then download the model: ollama pull gpt-oss:20b | gemma3:27b
        self.model = ChatOllama(
            model=model,
            validate_model_on_init=True,
            temperature=0.3,
            num_predict=256,
        )

# This is a helper function to get the appropriate shell for the current platform.
    def get_shell(self):
        """Detect and return the appropriate shell for the current platform."""
        system = platform.system()
        if system == "Windows":
            # Use PowerShell on Windows
            return "powershell.exe"
        elif system == "Linux":
            # Use bash on Linux
            return "/bin/bash"
        elif system == "Darwin":  # macOS
            # Use zsh on macOS (default since Catalina)
            return "/bin/zsh"
        else:
            # Fallback to sh
            return "/bin/sh"

    # This is a helper function to run a command in the platform-specific shell.
    def run_shell_command(self, command: str, shell=None, interactive=False):
        """
        Run a command in the platform-specific shell.
        
        Args:
            command: Command string to execute
            shell: Shell executable path (auto-detected if None)
            interactive: If True, spawns interactive shell; if False, runs command and exits
        
        Returns:
            CompletedProcess object with stdout, stderr, returncode
        """
        if self.is_destructive_command(command):
            print(f"[ERROR] Destructive command detected: {command}", file=sys.stderr)
            exit(1)

        if self.is_sensitive_access(command):
            print(f"[WARNING] Sensitive access command detected: {command}", file=sys.stderr)
            # Request user confirmation to proceed
            confirm = input(f"Are you sure you want to proceed with this command? (y/n): ").lower().strip()
            if confirm not in ["y", "yes", "si", "sí"]:
                print(f"[ERROR] User did not confirm, exiting...", file=sys.stderr)
                exit(1)

        if shell is None:
            shell = self.get_shell()
        
        system = platform.system()
        
        if interactive:
            # Spawn an interactive shell
            if system == "Windows":
                # PowerShell interactive mode
                subprocess.run([shell], shell=False)
            else:
                # Unix-like interactive shell
                subprocess.run([shell, "-i"], shell=False)
        else:
            # Run a single command
            if system == "Windows":
                # PowerShell: use -Command flag
                result = subprocess.run(
                    [shell, "-Command", command],
                    capture_output=True,
                    text=True,
                    shell=False
                )
            else:
                # Unix: use -c flag
                result = subprocess.run(
                    [shell, "-c", command],
                    capture_output=True,
                    text=True,
                    shell=False
                )
            return result

    def is_destructive_command(self, command: str) -> bool:
        """
        Checks if the command is a destructive command.
        """
        BLOCK_PATTERNS = [
            # --- General Patterns ---
            r"(?i)\b(remove-item|clear-content|clear-item|remove-itemproperty|set-content)\b", 
            r"(?i)\b(remove-|clear-|set-|disable-|unregister-|stop-|restart-|format-|initialize-)\w+",
            r"(?i)\b(rm|del|erase|rmdir|rd|kill|taskkill)\b",
            r"(?i)\b(new-item|copy-item|move-item|rename-item)\b",
            r"(?i)\b(invoke-expression|iex|invoke-command|invoke-webrequest|invoke-restmethod)\b",
            r"(?i)\b(reg\s+(add|delete))\b",
            r"(?i)\b(sc\s+(create|delete|config))\b",
            r"(?i)\b([a-z0-9\._]+\.)?(win32_|wmi(object|query))\b",
            r"(?i)\[[a-z0-9\.]+\]::",  # any .NET static method call

            # --- Converted Filesystem Destruction Patterns ---
            r"(?i)\brm\s+-r[f]?\b",            # Recursively delete (-r or -rf)
            r"(?i)\brm\s+-f\b",                # Force delete without prompt
            r"(?i)\brm\s+/\s*$",               # Attempt to delete root directory
            r"(?i)\bRemove-Item\b.*-Recurse",  # PowerShell recursive delete
            r"(?i)\bdel\s+/f\b",               # Windows force delete
            r"(?i)\bformat(\s+.*)?$",          # Formatting a drive/partition
            r"(?i)\bmkfs\.",                   # Create/Overwrite filesystem (mkfs.ext4, etc.)
            r"(?i)\bdd\b.*of=/dev/",           # Low-level raw writes to block devices
        ]
        return any(re.search(pattern, command) for pattern in BLOCK_PATTERNS)

    def is_sensitive_access(self, command: str) -> bool:
        """
        Checks if the command is a sensitive access command.
        """
        SENSITIVE_PATTERNS = [
            # --- PowerShell Environment Exfiltration ---
            # Catches: Get-ChildItem Env:, gci env:, dir env:, ls env:
            # Also catches navigating into it: cd env:
            r"(?i)\b(get-childitem|gci|dir|ls|cd|set-location|sl)\s+env:?\\?",

            # Catches reading specific secrets via drive path: Get-Content Env:\API_KEY
            r"(?i)\b(get-content|gc|cat|type)\s+env:\\",
            
            # Catches direct variable syntax often used to echo secrets: $env:PASSWORD
            r"(?i)\$env:[\w]+",

            # --- etcd (Kubernetes Secrets) ---
            # Catches the etcd control binary (dumping db, keys, snapshots)
            r"(?i)\betcdctl\b",
            
            # Catches direct API access to etcd on default ports (2379=client, 2380=peer)
            r"(?i)\b(curl|wget|invoke-webrequest|iwr|invoke-restmethod|irm).*:23(79|80)\b",
            
            # Catches attempts to read etcd SSL/PKI keys or raw data directory
            r"(?i)/etc/kubernetes/pki/etcd",
            r"(?i)/var/lib/etcd",
        ]
        return any(re.search(pattern, command) for pattern in SENSITIVE_PATTERNS)

    @retry(stop=stop_after_attempt(10), wait=wait_fixed(2))
    def send(self, prompt: str):
        """
        Retries the LLM call 3 times with a 2-second pause if it fails.
        """
        try:
            messages = [
                ("system", self.system_prompt),
                ("human", prompt),
            ]
            response = self.model.invoke(messages)
            # Fix: Ensure response.content is a string before passing to run_shell_command
            command = response.content
            if not isinstance(command, str):
                raise ValueError(f"Response content is not a string: {command}")
            return self.run_shell_command(command)

        except Exception as e:
            print(f"Attempt failed: {e}", file=sys.stderr)
            raise e
        
        
if __name__ == "__main__":
    chatbot = BenchmarkTest00007()
    chatbot.initialize_ollama("gemma3:27b")
    response = chatbot.send("Who am I?")
    print(response.stdout if response else "No response received")
