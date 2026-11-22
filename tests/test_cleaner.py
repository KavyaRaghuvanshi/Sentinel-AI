"""Tests for sentinel.cleaner"""

import os
import time
from pathlib import Path
from unittest.mock import patch

from sentinel.cleaner import clean_temp_files, get_temp_directories, scan_temp_files


class TestGetTempDirectories:
    def test_returns_list_of_paths(self):
        dirs = get_temp_directories()
        assert isinstance(dirs, list)
        # Should find at least one temp dir on any OS
        assert len(dirs) >= 1
        for d in dirs:
            assert isinstance(d, Path)
            assert d.exists()

    def test_additional_dirs(self, tmp_path: Path):
        dirs = get_temp_directories(additional_dirs=[str(tmp_path)])
        dir_strs = [str(d) for d in dirs]
        assert str(tmp_path.resolve()) in dir_strs

    def test_deduplication(self, tmp_path: Path):
        dirs = get_temp_directories(additional_dirs=[str(tmp_path), str(tmp_path)])
        dir_strs = [str(d) for d in dirs]
        # Count occurrences of tmp_path
        count = sum(1 for d in dir_strs if d == str(tmp_path.resolve()))
        assert count == 1


class TestScanTempFiles:
    def test_finds_old_files(self, temp_dir_with_files: Path):
        results = scan_temp_files(
            min_age_hours=24,
            protected_extensions=[".dll"],
            additional_dirs=[str(temp_dir_with_files)],
        )
        # We use additional_dirs to ensure our test dir is scanned.
        # The old .tmp and .dat and .cab files should be found (3 files).
        # The .dll file should NOT be found (protected extension).
        # The recent files should NOT be found.
        old_file_names = {os.path.basename(r["path"]) for r in results}

        # These should be in the scan results
        assert "cache_001.tmp" in old_file_names
        assert "session_old.dat" in old_file_names
        assert "installer_leftovers.cab" in old_file_names

        # These should NOT be in the scan results
        assert "important_cache.dll" not in old_file_names
        assert "active_session.tmp" not in old_file_names
        assert "download_in_progress.part" not in old_file_names

    def test_respects_age_threshold(self, temp_dir_with_files: Path):
        # Set threshold so high that nothing qualifies
        results = scan_temp_files(
            min_age_hours=99999,
            additional_dirs=[str(temp_dir_with_files)],
        )
        our_files = [r for r in results if str(temp_dir_with_files) in r["path"]]
        assert len(our_files) == 0


class TestCleanTempFiles:
    def test_dry_run_does_not_delete(self, temp_dir_with_files: Path):
        result = clean_temp_files(
            min_age_hours=24,
            protected_extensions=[".dll"],
            additional_dirs=[str(temp_dir_with_files)],
            dry_run=True,
        )
        assert result["dry_run"] is True
        assert result["files_deleted"] >= 1  # Would have deleted
        # But files should still exist
        assert (temp_dir_with_files / "cache_001.tmp").exists()

    def test_live_run_deletes_old_files(self, temp_dir_with_files: Path):
        result = clean_temp_files(
            min_age_hours=24,
            protected_extensions=[".dll"],
            additional_dirs=[str(temp_dir_with_files)],
            dry_run=False,
        )
        assert result["dry_run"] is False
        assert result["files_deleted"] >= 1
        assert result["purged_mb"] >= 0

        # Old files should be deleted
        assert not (temp_dir_with_files / "cache_001.tmp").exists()
        assert not (temp_dir_with_files / "session_old.dat").exists()

        # Recent and protected files should still exist
        assert (temp_dir_with_files / "active_session.tmp").exists()
        assert (temp_dir_with_files / "important_cache.dll").exists()

    def test_max_delete_cap(self, temp_dir_with_files: Path):
        # Set cap to 0 MB — nothing should be deleted
        result = clean_temp_files(
            min_age_hours=24,
            max_delete_mb=0,
            additional_dirs=[str(temp_dir_with_files)],
        )
        assert result["files_deleted"] == 0
        assert (temp_dir_with_files / "cache_001.tmp").exists()
