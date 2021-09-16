import hashlib
import json
from urllib.parse import urlparse
from dojo.models import Endpoint, Finding


class PylintParser(object):
    """
    Parse Pylint JSON reports.
    """

    def get_scan_types(self):
        return ["Pylint Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Pylint Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Pylint report file can be imported in JSON format (option --json)."

    def get_findings(self, file, test):
        data = json.load(file)
        finding_list = []
        for content in data:
            severity = ''
            file_path = ''
            line = -1
            title = ''
            finding_detail = ''

            if 'type' in content:
                severity = self.convert_severity(content['type'])

            if 'path' in content:
                file_path = content['path']

            if 'line' in content:
                line = content['line']
                finding_detail += 'L' + str(line)

            if 'column' in content:
                finding_detail += 'C' + str(content['column']) + ' - '

            if 'message' in content:
                finding_detail += str(content['message'])

            if 'symbol' in content:
                title += str(content["symbol"])
            else:
                title += str("Finding Not defined")

            if 'message-id' in content:
                title += ' Test ID: ' + str(content["message-id"])

            finding = Finding(title=title,
                              test=test,
                              description=finding_detail,
                              severity=severity,
                              file_path=file_path,
                              line=line,
                              url='N/A',
                              static_finding=True,
                              mitigation='N/A',
                              impact='N/A')
            finding_list.append(finding)

        return list(finding_list)

    def convert_severity(self, pylint_serverity):
        """Convert severity value"""
        if pylint_serverity == "fatal":
            return "Critical"
        elif pylint_serverity == "error":
            return "High"
        elif pylint_serverity == "warning":
            return "Medium"
        elif pylint_serverity == "refactor":
            return "Low"
        else:
            return "Informational"
