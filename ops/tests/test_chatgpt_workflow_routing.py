"""Offline: receipt routing must remain optional and never alter text-only orders."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


class WorkflowMediaRouting(unittest.TestCase):
    def test_owner_issue_is_still_required_and_text_only_untouched(self):
        workflow = (ROOT / '.github/workflows/coordinator-owner-order.yml').read_text()
        self.assertIn("github.event.issue.user.login == github.repository_owner", workflow)
        self.assertIn("startsWith(github.event.issue.title, '[coordinator run] ')", workflow)
        self.assertIn("bash -s -- '$job' dispatch '$order_b64'", workflow)
        self.assertIn("coordinator_owner_asset_id.txt", workflow)
        self.assertNotIn('private-user-images.githubusercontent.com', workflow)
        self.assertNotIn('upload-artifact', workflow)

    def test_non_public_selected_id_cannot_skip_secure_validation(self):
        workflow = (ROOT / '.github/workflows/coordinator-owner-order.yml').read_text()
        remote = (ROOT / 'ops/coordinator-smoke-remote.sh').read_text()
        self.assertIn('COORDINATOR_ATTACHMENTS_ID=', workflow)
        self.assertIn("re.fullmatch(r'COORDINATOR_ATTACHMENTS_ID=([0-9a-f]{32})'", workflow)
        self.assertIn('with-private-attachments', remote)
        self.assertIn('source_reference', remote)
        self.assertIn('mv -T -- "$original_bundle" "$asset_bundle"', remote)
        self.assertIn('asset_args=(--attachment-bundle "$asset_bundle")', remote)
        self.assertIn('cleanup_private_workspace()', remote)
        self.assertIn('COORDINATOR_ATTACHMENTS_REFUSED', workflow)

    def test_mcp_backend_and_video_contract_still_separate(self):
        media = (ROOT / 'ops/coordinator_media.py').read_text()
        self.assertIn('def verify(directory:', media)
        self.assertIn('def prepare(directory:', media)
        bridge = (ROOT / 'ops/chatgpt_attachment_ingress.py').read_text()
        self.assertIn('def stage(', bridge)
        self.assertNotIn('issue.create', bridge)
        self.assertNotIn('github.create_issue', bridge)
        self.assertNotIn('subprocess.run', bridge)


if __name__ == '__main__':
    unittest.main()