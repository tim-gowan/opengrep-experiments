"""Type definitions and data models for Holocron."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class Confidence:
    """Confidence levels for stitching matches."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    
    @staticmethod
    def explain(level: str) -> str:
        """Explain what a confidence level means."""
        explanations = {
            "HIGH": "Direct match with full resolution - all required information available",
            "MEDIUM": "Match with inference or partial resolution - some uncertainty",
            "LOW": "Weak inference - requires significant assumptions, high risk of false positive"
        }
        return explanations.get(level, "Unknown confidence level")


@dataclass
class Match:
    """Represents a stitched match between source and sink findings."""
    strategy: str
    source: str
    sink: str
    confidence: str
    source_idx: int
    sink_idx: int
    source_path: str
    source_line: int
    sink_path: str
    sink_line: int
    resolution: Optional[str] = None
    note: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'strategy': self.strategy,
            'source': self.source,
            'sink': self.sink,
            'confidence': self.confidence,
            'source_idx': self.source_idx,
            'sink_idx': self.sink_idx,
            'source_path': self.source_path,
            'source_line': self.source_line,
            'sink_path': self.sink_path,
            'sink_line': self.sink_line,
            'resolution': self.resolution,
            'note': self.note
        }


@dataclass
class ParameterInfo:
    """Enhanced parameter information."""
    name: str
    position: int
    annotation: Optional[str] = None
    default: Optional[str] = None
    kind: str = "POSITIONAL_OR_KEYWORD"  # POSITIONAL_ONLY, POSITIONAL_OR_KEYWORD, VAR_POSITIONAL, KEYWORD_ONLY, VAR_KEYWORD
    usage_context: Dict[str, Any] = field(default_factory=lambda: {
        'assigned_to_fields': [],
        'passed_to_calls': [],
        'returned': False
    })


@dataclass
class ClassIndex:
    """Class index structure."""
    classes: Dict[str, Any]
    functions: Dict[str, Any]
    imports: Dict[str, Any]
    attributes: Dict[str, Any]
    inheritance: Dict[str, Any]
    method_calls: List[Dict[str, Any]]
    repository: Optional[Dict[str, Any]] = None  # Repository info: {id, url, root_path}
    repositories: Optional[Dict[str, Dict[str, Any]]] = None  # Repo-scoped indices: repo_id -> index
    cross_repo_calls: Optional[List[Dict[str, Any]]] = None  # Cross-repository call tracking
    files: Optional[Dict[str, Dict[str, Any]]] = None  # Per-file exports and metadata

