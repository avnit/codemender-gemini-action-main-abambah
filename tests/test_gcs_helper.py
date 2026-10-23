#!/usr/bin/env python3
"""
Unit tests for worker/gcs_helper.py:
- GCS URI parsing
- Upload logic mocking
"""

import sys
import unittest
from unittest.mock import MagicMock, patch

from gcs_helper import parse_gcs_uri, upload_file


class TestGCSHelper(unittest.TestCase):
    def test_parse_gcs_uri(self):
        bucket, blob = parse_gcs_uri("gs://my-bucket/scans/exec-1/matrix.json")
        self.assertEqual(bucket, "my-bucket")
        self.assertEqual(blob, "scans/exec-1/matrix.json")

        bucket, blob = parse_gcs_uri("gs://simple-bucket")
        self.assertEqual(bucket, "simple-bucket")
        self.assertEqual(blob, "")

        with self.assertRaises(ValueError):
            parse_gcs_uri("https://storage.googleapis.com/my-bucket/test")

    def test_upload_file(self):
        mock_storage = MagicMock()
        mock_client = MagicMock()
        mock_bucket = MagicMock()
        mock_blob = MagicMock()

        mock_storage.Client.return_value = mock_client
        mock_client.bucket.return_value = mock_bucket
        mock_bucket.blob.return_value = mock_blob

        mock_cloud = MagicMock()
        mock_cloud.storage = mock_storage

        with patch.dict(sys.modules, {"google": MagicMock(), "google.cloud": mock_cloud, "google.cloud.storage": mock_storage}):
            upload_file("/tmp/matrix.json", "gs://my-bucket/scans/exec-123/matrix.json")

        mock_client.bucket.assert_called_once_with("my-bucket")
        mock_bucket.blob.assert_called_once_with("scans/exec-123/matrix.json")
        mock_blob.upload_from_filename.assert_called_once_with("/tmp/matrix.json")


if __name__ == "__main__":
    unittest.main()
