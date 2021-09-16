from django.test import TestCase
from dojo.tools.pylint.parser import PylintParser
from dojo.models import Test


class TestPylintParser(TestCase):

    def test_pylint_parser_with_no_vuln_has_no_findings(self):
        testfile = open("dojo/unittests/scans/pylint/pylint_zero_vul.json")
        parser = PylintParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_pylint_parser_with_one_criticle_vuln_has_one_findings(self):
        testfile = open("dojo/unittests/scans/pylint/pylint_one_vul.json")
        parser = PylintParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("bad-indentation Test ID: W0311", finding.title)
        self.assertEqual("L9C0 - Bad indentation. Found 3 spaces, expected 4", finding.description)
        self.assertEqual("a.py", finding.file_path)
        self.assertEqual(9, finding.line)

    def test_pylint_parser_with_many_vuln_has_many_findings(self):
        testfile = open("dojo/unittests/scans/pylint/pylint_many_vul.json")
        parser = PylintParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(5, len(findings))
        self.assertEqual("Informational", findings[0].severity)
        self.assertEqual("Low", findings[1].severity)
        self.assertEqual("Medium", findings[2].severity)
        self.assertEqual("High", findings[3].severity)
        self.assertEqual("Critical", findings[4].severity)
        self.assertEqual("fatal symbol Test ID: f-1", findings[4].title)
        self.assertEqual("L5C5 - fatal message", findings[4].description)
        self.assertEqual("e.py", findings[4].file_path)
        self.assertEqual(5, findings[4].line)

    def test_fail(self):
        self.assertEqual(True, False)
