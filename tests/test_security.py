"""Offline source and artifact checks. No target network requests."""
import datetime
from html.parser import HTMLParser
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]

class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.page = Page()
        self.page.feed((ROOT / 'index.html').read_text())

    def test_csp_and_no_inline_execution(self):
        policy = next(a['content'] for t, a in self.page.tags
                      if t == 'meta' and a.get('http-equiv') == 'Content-Security-Policy')
        for directive in ("default-src 'none'", "script-src 'self'", "style-src 'self'",
                          "object-src 'none'", "base-uri 'none'", "form-action 'none'"):
            self.assertIn(directive, policy)
        self.assertNotIn('unsafe-', policy)
        for tag, attrs in self.page.tags:
            self.assertFalse(any(k.lower().startswith('on') or k == 'style' for k in attrs))
            self.assertNotEqual(tag, 'style')
            if tag == 'script':
                self.assertEqual(attrs.get('src'), 'assets/site.js')
        script = (ROOT / 'assets/site.js').read_text()
        self.assertIsNone(re.search(r'innerHTML|outerHTML|document.write|eval\s*\(|new Function', script))

    def test_links_and_resources(self):
        ids = {a['id'] for _, a in self.page.tags if 'id' in a}
        for tag, attrs in self.page.tags:
            for key in ('href', 'src'):
                value = attrs.get(key, '')
                if value.startswith('#'):
                    if value[1:]: self.assertIn(value[1:], ids)
                elif value.startswith('mailto:'):
                    self.assertEqual(value, 'mailto:info@redsec.be')
                elif value:
                    self.assertNotIn(':', value)
                    self.assertTrue((ROOT / value).is_file(), value)
            if attrs.get('target') == '_blank':
                self.assertIn('noopener', attrs.get('rel', '').split())
            if 'aria-controls' in attrs:
                self.assertIn(attrs['aria-controls'], ids)

    def test_security_contact(self):
        fields = dict(line.split(': ', 1) for line in
                      (ROOT / '.well-known/security.txt').read_text().splitlines())
        self.assertEqual(fields['Contact'], 'mailto:info@redsec.be')
        self.assertEqual(fields['Canonical'], 'https://www.redsec.be/.well-known/security.txt')
        expiry = datetime.datetime.fromisoformat(fields['Expires'].replace('Z', '+00:00'))
        now = datetime.datetime.now(datetime.timezone.utc)
        self.assertGreater(expiry, now, 'Renew security.txt')
        self.assertLess(expiry - now, datetime.timedelta(days=366))
        self.assertIn('- .well-known', (ROOT / '_config.yml').read_text())
        self.assertEqual((ROOT / 'CNAME').read_text().strip(), 'www.redsec.be')

    def test_no_sensitive_deployment_files(self):
        # Inspect public source paths; allow documented examples only if explicitly reviewed.
        for path in ROOT.rglob('*'):
            if not path.is_file() or '.git' in path.parts or '__pycache__' in path.parts:
                continue
            name = path.name.lower()
            self.assertFalse(name.startswith('.env') or name in {'id_rsa', 'id_ed25519'})
            self.assertFalse(name.endswith(('.php', '.bak', '.sql', '.dump', '.pem', '.key', '.p12', '.log', '.tmp', '.zip')), str(path))
        config = (ROOT / '_config.yml').read_text()
        for name in ('docs', 'tests', 'SECURITY.md'):
            self.assertIn('- ' + name, config)

if __name__ == '__main__':
    unittest.main()
