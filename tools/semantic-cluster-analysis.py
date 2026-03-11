import json
import os
import argparse
import traceback
from collections import Counter
import itertools

class Location:
    """
    Represents a location within a file, as defined in a SARIF report.

    Attributes:
        id (int): The ID of the location.
        uri (str): The URI of the file.
        uriBaseId (str): The base ID for the URI.
        start_line (int): The starting line number of the code snippet.
        start_column (int): The starting column number of the code snippet.
        end_line (int): The ending line number of the code snippet.
        end_column (int): The ending column number of the code snippet.
        file_path (str): The local file path of the code snippet.
        segment (str): The code snippet extracted from the file.
        extended_segment (str): An extended version of the code snippet (not currently used).
    """
    def __init__(self, location, repo):
        """
        Initializes a Location object.

        Args:
            location (dict): A dictionary containing location information from the SARIF report.
            repo (str): The path to the repository.
        """
        self.id = location['id']
        self.uri = location['physicalLocation']['artifactLocation']['uri']
        self.uriBaseId = location['physicalLocation']['artifactLocation']['uriBaseId']
        self.start_line = location['physicalLocation']['region']['startLine']
        self.start_column = location['physicalLocation']['region']['startColumn']
        self.end_line = location['physicalLocation']['region']['endLine']
        self.end_column = location['physicalLocation']['region']['endColumn']
        self.file_path = self.get_file_path_local(location, repo)
        self.segment, self.extended_segment = self.get_segment_local(self.file_path)

    def get_segment_local(self, file_path):
        """
        Extracts a code snippet from a file based on the location's coordinates.

        Args:
            file_path (str): The path to the file.

        Returns:
            tuple: A tuple containing the code snippet and the extended segment.
        """
        segment = ""
        extended_segment = ""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
                # Extract the primary segment
                if self.start_line == self.end_line:
                    line = lines[self.start_line - 1]
                    segment += line[self.start_column - 1:self.end_column]
                else:
                    for i in range(self.start_line - 1, self.end_line):
                        if i == self.start_line - 1:
                            line = lines[i]
                            segment += line[self.start_column - 1:]
                        elif i == self.end_line - 1:
                            line = lines[i]
                            segment += line[:self.end_column]
                        else:
                            segment += lines[i]

                # Extract the extended segment
                start_line_idx = self.start_line - 1
                
                # Find the start of the function call
                line_num = start_line_idx
                temp_segment = ""
                while line_num >= 0:
                    line = lines[line_num]
                    if line_num == start_line_idx:
                        temp_segment = line[:self.start_column-1] + temp_segment
                    else:
                        temp_segment = line + temp_segment

                    if '(' in line:
                        break
                    line_num -= 1
                
                # Find the end of the function call
                line_num = start_line_idx
                open_paren_count = temp_segment.count('(')
                close_paren_count = temp_segment.count(')')
                
                temp_segment += segment

                while line_num < len(lines):
                    if line_num == start_line_idx:
                         line_part = lines[line_num][self.end_column-1:]
                         temp_segment += line_part
                         open_paren_count += line_part.count('(')
                         close_paren_count += line_part.count(')')
                    elif line_num > start_line_idx:
                        line = lines[line_num]
                        temp_segment += line
                        open_paren_count += line.count('(')
                        close_paren_count += line.count(')')
                    
                    if open_paren_count > 0 and open_paren_count == close_paren_count:
                        break
                    line_num += 1
                extended_segment = temp_segment

        except Exception as e:
            print(f"Error in get_snippet_local: {e}")
            print(f"Error: Could not read file {file_path}")
            print(f" Location: {self.start_line}:{self.start_column}-{self.end_line}:{self.end_column}")
            traceback.print_exc()
            exit(1)
        return segment, extended_segment.strip()

    def get_file_path_local(self, location, repo_path):
        """
        Constructs the local file path for a given location.

        Args:
            location (dict): The location dictionary from the SARIF report.
            repo_path (str): The path to the repository.

        Returns:
            str: The full local file path.
        """
        try:
            file_path = os.path.join(repo_path, location['physicalLocation']['artifactLocation']['uri'])
        except Exception as e:
            traceback.print_exc() ## nosemgrep
            exit(1)
        return file_path 


def count_results_by_ruleId(sarif_data):
    """
    Parses a SARIF object and counts the number of results for each rule.

    Args:
        sarif_data (dict): A dictionary representing the SARIF JSON data.

    Returns:
        dict: A dictionary with ruleId as keys and details about each rule's occurrences.
    """
    rule_counts = {}
    if 'runs' not in sarif_data:
        return rule_counts

    for run in sarif_data['runs']:
        if 'results' not in run:
            continue
        for i, result in enumerate(run['results']):
            rule_id = result.get('ruleId')
            if rule_id:
                if rule_id not in rule_counts:
                    rule_counts[rule_id] = {'count': 0, 'indices': [], 'codeFlows': []}
                rule_counts[rule_id]['indices'].append(i)
                rule_counts[rule_id]['count'] += 1
                if 'codeFlows' in result:
                    rule_counts[rule_id]['codeFlows'].append(result['codeFlows'])
    
    rule_counts = dict(sorted(rule_counts.items(), key=lambda item: item[1]['count'], reverse=True))
    return rule_counts


def get_sarif_local(filename):
    """
    Loads a SARIF file from the local filesystem.

    Args:
        filename (str): The path to the SARIF file.

    Returns:
        dict: A dictionary representing the SARIF JSON data.
    """
    with open(filename, 'r') as f:
        return json.load(f)


def get_hotspot(rule_counts, repo_path, rule_name=None):
    """
    Identifies hotspots for a given rule by analyzing code snippets.

    Args:
        rule_counts (dict): A dictionary of rule counts from the SARIF report.
        repo_path (str): The path to the repository.
        rule_name (str, optional): The specific rule to analyze. Defaults to None.

    Returns:
        tuple: A tuple containing the number of findings and dictionaries for sources, propagators, and sinks.
    """
    sources = {}
    propagators = {}
    sinks = {}
    findings_count = 0
    if rule_name in rule_counts and 'codeFlows' in rule_counts[rule_name]:
        all_code_flows = rule_counts[rule_name]['codeFlows']
        findings_count = rule_counts[rule_name]['count']
        
        for code_flow_list in all_code_flows:
            for code_flow in code_flow_list:
                for thread_flow in code_flow['threadFlows']:
                    locations = thread_flow['locations']
                    num_locations = len(locations)
                    for i, loc_ref in enumerate(locations):
                        location = loc_ref['location']
                        location_object = Location(location, repo_path)
                        instance_details = {
                            'file_path': location_object.file_path,
                            'extended_segment': location_object.extended_segment,
                            'index': i,
                            'locations': num_locations
                        }
                        
                        hotspot_category = None
                        if num_locations == 1:
                            hotspot_category = sinks
                        elif i == 0:
                            hotspot_category = sources
                        elif i == num_locations - 1:
                            hotspot_category = sinks
                        else:
                            hotspot_category = propagators
                        
                        hotspot_category.setdefault(location_object.segment, {'count': 0, 'instances': []})
                        hotspot_category[location_object.segment]['count'] += 1
                        hotspot_category[location_object.segment]['instances'].append(instance_details)

    sources = dict(sorted(sources.items(), key=lambda item: item[1]['count'], reverse=True))
    propagators = dict(sorted(propagators.items(), key=lambda item: item[1]['count'], reverse=True))
    sinks = dict(sorted(sinks.items(), key=lambda item: item[1]['count'], reverse=True))
    
    return findings_count, sources, propagators, sinks


def main():
    """
    Main function to parse arguments, analyze SARIF data, and write hotspots to a file.
    """
    parser = argparse.ArgumentParser(description='Analyze SARIF files to find hotspots.')
    parser.add_argument('--sarif', required=True, help='Path to the SARIF file.')
    parser.add_argument('--repo', required=True, help='Path to the repository.')
    parser.add_argument('--output', required=True, help='Path to the output file.')
    parser.add_argument('--print-locations', action='store_true', help='Print file paths for each hotspot.')
    parser.add_argument('--print-extended', action='store_true', help='Print the extended segment for each hotspot.')
    args = parser.parse_args()

    sarif_json = get_sarif_local(args.sarif)
    rule_counts = count_results_by_ruleId(sarif_json)

    with open(args.output, 'w') as f:
        for rule_id in rule_counts.keys():
            findings_count, sources, propagators, sinks = get_hotspot(rule_counts, args.repo, rule_name=rule_id)
    with open(args.output, 'w') as f:
        for rule_id in rule_counts.keys():
            findings_count, sources, propagators, sinks = get_hotspot(rule_counts, args.repo, rule_name=rule_id)
            if findings_count > 0:
                f.write(f"{rule_id}: {findings_count} findings\n")

                f.write("  Sinks:\n")
                if sinks:
                    for segment, details in sinks.items():
                        f.write(f"    [{details['count']}] {segment.strip()}\n")
                        if args.print_locations or args.print_extended:
                            for i, instance in enumerate(details['instances']):
                                f.write(f"          Instance_{i+1}: {{\n")
                                if args.print_locations:
                                    f.write(f"          'file_path': '{instance['file_path']}',\n")
                                if args.print_extended:
                                    f.write(f"          'extended_segment': \"{instance['extended_segment'].replace('\"', '\\\"')}\",\n")
                                    f.write(f"          'index': {instance['index']},\n")
                                    f.write(f"          'locations': {instance['locations']}\n")
                                f.write("    }\n")
                                                
                f.write("  Sources:\n")
                if sources:
                    for segment, details in sources.items():
                        f.write(f"    [{details['count']}] {segment.strip()}\n")
                        if args.print_locations or args.print_extended:
                            for i, instance in enumerate(details['instances']):
                                f.write(f"          Instance_{i+1}: {{\n")
                                if args.print_locations:
                                    f.write(f"          'file_path': '{instance['file_path']}',\n")
                                if args.print_extended:
                                    f.write(f"          'extended_segment': \"{instance['extended_segment'].replace('\"', '\\\"')}\",\n")
                                    f.write(f"          'index': {instance['index']},\n")
                                    f.write(f"          'locations': {instance['locations']}\n")
                                f.write("    }\n")
                
                f.write("  Propagators:\n")
                if propagators:
                    for segment, details in propagators.items():
                        f.write(f"    [{details['count']}] {segment.strip()}\n")
                        if args.print_locations or args.print_extended:
                            for i, instance in enumerate(details['instances']):
                                f.write(f"          Instance_{i+1}: {{\n")
                                if args.print_locations:
                                    f.write(f"          'file_path': '{instance['file_path']}',\n")
                                if args.print_extended:
                                    f.write(f"          'extended_segment': \"{instance['extended_segment'].replace('\"', '\\\"')}\",\n")
                                    f.write(f"          'index': {instance['index']},\n")
                                    f.write(f"          'locations': {instance['locations']}\n")
                                f.write("    }\n")


if __name__ == '__main__':
    main()
