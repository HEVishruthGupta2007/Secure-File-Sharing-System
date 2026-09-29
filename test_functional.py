"""
Comprehensive Functional Test Pass for CodSoft Task 5 - Secure File Sharing System.
Covers all requirements 5a through 5g specified in the project requirements.
"""

import os
import sys
from pathlib import Path
from datetime import datetime, timedelta

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from dotenv import load_dotenv
load_dotenv(BASE_DIR / ".env")

from app import create_app
from app.extensions import db
from app.models import User, FileRecord, FileShare, ShareLink, utcnow


def run_tests():
    print("=" * 70)
    print("RUNNING COMPREHENSIVE FUNCTIONAL TEST SUITE (CodSoft Task 5)")
    print("=" * 70)

    # Initialize app with test client
    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    with app.app_context():
        # Clean test database tables and upload files
        db.drop_all()
        db.create_all()
        
        # Clean uploads folder
        upload_dir = Path(app.config["UPLOAD_DIR"])
        if upload_dir.exists():
            for f in upload_dir.iterdir():
                if f.is_file():
                    f.unlink()

    client = app.test_client()

    # -------------------------------------------------------------------------
    # 5a. Register two separate user accounts (first becomes admin)
    # -------------------------------------------------------------------------
    print("\n[TEST 5a] Register two separate user accounts (first becomes admin)...")
    
    # Register first user -> should be admin
    resp1 = client.post("/auth/register", data={
        "username": "alice_admin",
        "email": "alice@example.com",
        "password": "password123"
    }, follow_redirects=True)
    assert resp1.status_code == 200, f"Register alice failed: {resp1.status_code}"

    # Log out alice
    client.get("/auth/logout", follow_redirects=True)

    # Register second user -> should be regular user
    resp2 = client.post("/auth/register", data={
        "username": "bob_user",
        "email": "bob@example.com",
        "password": "password123"
    }, follow_redirects=True)
    assert resp2.status_code == 200, f"Register bob failed: {resp2.status_code}"

    # Log out bob
    client.get("/auth/logout", follow_redirects=True)

    with app.app_context():
        u1 = User.query.filter_by(username="alice_admin").first()
        u2 = User.query.filter_by(username="bob_user").first()
        assert u1 is not None, "alice_admin not found in database"
        assert u2 is not None, "bob_user not found in database"
        assert u1.is_admin() and u1.role == "admin", f"Expected alice to be admin, got {u1.role}"
        assert not u2.is_admin() and u2.role == "user", f"Expected bob to be user, got {u2.role}"
        print(f"  --> User 1 registered: '{u1.username}' with role='{u1.role}' (is_admin={u1.is_admin()})")
        print(f"  --> User 2 registered: '{u2.username}' with role='{u2.role}' (is_admin={u2.is_admin()})")
    print("  [PASS] Test 5a passed successfully.")

    # -------------------------------------------------------------------------
    # 5b. Upload a file as user A; confirm bytes on disk are NOT plaintext
    # -------------------------------------------------------------------------
    print("\n[TEST 5b] Upload a file as user A (alice); confirm ciphertext on disk...")
    # Log in as alice
    client.post("/auth/login", data={
        "identifier": "alice_admin",
        "password": "password123"
    }, follow_redirects=True)

    test_content = b"SECRET_PLAINTEXT_PAYLOAD_12345_TOP_SECRET"
    import io
    data = {
        "file": (io.BytesIO(test_content), "alice_document.txt")
    }
    upload_resp = client.post("/files/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert upload_resp.status_code == 200, f"Upload failed: {upload_resp.status_code}"

    with app.app_context():
        record = FileRecord.query.filter_by(original_filename="alice_document.txt").first()
        assert record is not None, "alice_document.txt not found in database"
        alice_file_id = record.id
        stored_path = Path(app.config["UPLOAD_DIR"]) / record.stored_filename
        assert stored_path.exists(), f"Stored file {stored_path} does not exist on disk"

        disk_bytes = stored_path.read_bytes()
        print(f"  --> Original plaintext: {test_content.decode()}")
        print(f"  --> Stored filename on disk: {record.stored_filename}")
        print(f"  --> Stored raw bytes (first 50 bytes): {disk_bytes[:50]}")
        
        # Verify bytes on disk are NOT plaintext
        assert test_content not in disk_bytes, "CRITICAL ERROR: Plaintext found in file on disk!"
        assert disk_bytes.startswith(b"gAAAAA"), "Encrypted file should be a valid Fernet token starting with gAAAAA"
        print("  --> Verified: File on disk is genuinely encrypted Fernet ciphertext.")
    print("  [PASS] Test 5b passed successfully.")

    # -------------------------------------------------------------------------
    # 5c. Attempt to download user A's file as user B with no access -> 403
    # -------------------------------------------------------------------------
    print("\n[TEST 5c] Attempt to download alice's file as bob (unauthorized) -> must 403...")
    client.get("/auth/logout", follow_redirects=True)

    # Log in as bob
    client.post("/auth/login", data={
        "identifier": "bob_user",
        "password": "password123"
    }, follow_redirects=True)

    # Try downloading alice's file
    unauth_resp = client.get(f"/files/{alice_file_id}/download")
    print(f"  --> Bob attempted download of alice's file: status code = {unauth_resp.status_code}")
    assert unauth_resp.status_code == 403, f"Expected 403 Forbidden, got {unauth_resp.status_code}"
    print("  --> Verified: 403 Forbidden properly returned for unauthorized download attempt.")
    print("  [PASS] Test 5c passed successfully.")

    # -------------------------------------------------------------------------
    # 5d. Share file from A to B; confirm B can download and content matches exactly
    # -------------------------------------------------------------------------
    print("\n[TEST 5d] Share file from alice to bob; confirm bob can download matching content...")
    client.get("/auth/logout", follow_redirects=True)

    # Log in as alice to share the file
    client.post("/auth/login", data={
        "identifier": "alice_admin",
        "password": "password123"
    }, follow_redirects=True)

    share_resp = client.post(f"/files/{alice_file_id}/share", data={
        "username": "bob_user",
        "permission": "download"
    }, follow_redirects=True)
    assert share_resp.status_code == 200

    # Log out alice, log in as bob
    client.get("/auth/logout", follow_redirects=True)
    client.post("/auth/login", data={
        "identifier": "bob_user",
        "password": "password123"
    }, follow_redirects=True)

    # Bob downloads the shared file
    bob_download_resp = client.get(f"/files/{alice_file_id}/download")
    assert bob_download_resp.status_code == 200, f"Expected 200, got {bob_download_resp.status_code}"
    downloaded_data = bob_download_resp.data
    assert downloaded_data == test_content, f"Content mismatch! Expected {test_content}, got {downloaded_data}"
    print(f"  --> Bob downloaded shared file successfully.")
    print(f"  --> Downloaded content exact match: {downloaded_data.decode()}")
    print("  [PASS] Test 5d passed successfully.")

    # -------------------------------------------------------------------------
    # 5e. Generate a temporary link; usable without login; content correct
    # -------------------------------------------------------------------------
    print("\n[TEST 5e] Generate a temporary link; usable without login...")
    client.get("/auth/logout", follow_redirects=True)

    # Log in as alice to generate link
    client.post("/auth/login", data={
        "identifier": "alice_admin",
        "password": "password123"
    }, follow_redirects=True)

    link_resp = client.post(f"/files/{alice_file_id}/link", data={
        "minutes": 30
    }, follow_redirects=True)
    assert link_resp.status_code == 200

    with app.app_context():
        link_record = ShareLink.query.filter_by(file_id=alice_file_id).order_by(ShareLink.id.desc()).first()
        assert link_record is not None, "ShareLink was not created in database"
        link_token = link_record.token
        print(f"  --> Generated link token: {link_token}")

    # Use completely unauthenticated client (anonymous / no cookies)
    anon_client = app.test_client()
    anon_resp = anon_client.get(f"/files/link/{link_token}")
    assert anon_resp.status_code == 200, f"Expected 200 for public temporary link, got {anon_resp.status_code}"
    assert anon_resp.data == test_content, f"Temporary link content mismatch! Got {anon_resp.data}"
    print(f"  --> Anonymous client downloaded file via temporary link: status code = {anon_resp.status_code}")
    print(f"  --> Downloaded content exact match: {anon_resp.data.decode()}")
    print("  [PASS] Test 5e passed successfully.")

    # -------------------------------------------------------------------------
    # 5f. Manually expire that link; confirm returns 410 Gone
    # -------------------------------------------------------------------------
    print("\n[TEST 5f] Manually expire the temporary link; confirm returns 410 Gone...")
    with app.app_context():
        link_to_expire = ShareLink.query.filter_by(token=link_token).first()
        # Set expiry to 1 hour in the past
        link_to_expire.expires_at = utcnow() - timedelta(hours=1)
        db.session.commit()
        assert link_to_expire.is_expired(), "Link should be marked as expired"

    expired_resp = anon_client.get(f"/files/link/{link_token}")
    print(f"  --> Request to expired link: status code = {expired_resp.status_code}")
    assert expired_resp.status_code == 410, f"Expected 410 Gone, got {expired_resp.status_code}"
    print("  --> Verified: 410 Gone correctly returned after link expiry.")
    print("  [PASS] Test 5f passed successfully.")

    # -------------------------------------------------------------------------
    # 5g. Admin can see & manage all files; non-admin cannot see unshared files
    # -------------------------------------------------------------------------
    print("\n[TEST 5g] RBAC: Admin sees & manages all files; non-admin cannot see unshared files...")
    # Log out alice before logging in as bob
    client.get("/auth/logout", follow_redirects=True)
    # Log in as bob (user) and upload bob's private file
    login_bob_resp = client.post("/auth/login", data={
        "identifier": "bob_user",
        "password": "password123"
    }, follow_redirects=True)
    assert login_bob_resp.status_code == 200

    bob_content = b"BOB_PRIVATE_REPORT_CLASSIFIED"
    bob_upload_data = {
        "file": (io.BytesIO(bob_content), "bob_private.txt")
    }
    client.post("/files/upload", data=bob_upload_data, content_type="multipart/form-data", follow_redirects=True)

    with app.app_context():
        bob_record = FileRecord.query.filter_by(original_filename="bob_private.txt").first()
        assert bob_record is not None
        bob_file_id = bob_record.id

    # Log in as alice (admin) and upload alice's secret file (not shared with bob)
    client.get("/auth/logout", follow_redirects=True)
    client.post("/auth/login", data={
        "identifier": "alice_admin",
        "password": "password123"
    }, follow_redirects=True)

    alice_secret_content = b"ALICE_ADMIN_ONLY_CONFIDENTIAL"
    alice_secret_upload = {
        "file": (io.BytesIO(alice_secret_content), "alice_secret.txt")
    }
    client.post("/files/upload", data=alice_secret_upload, content_type="multipart/form-data", follow_redirects=True)

    with app.app_context():
        alice_secret_rec = FileRecord.query.filter_by(original_filename="alice_secret.txt").first()
        assert alice_secret_rec is not None
        alice_secret_id = alice_secret_rec.id

    # 1. Non-admin check: bob's dashboard
    client.get("/auth/logout", follow_redirects=True)
    client.post("/auth/login", data={
        "identifier": "bob_user",
        "password": "password123"
    }, follow_redirects=True)

    bob_dash = client.get("/files/")
    assert bob_dash.status_code == 200
    bob_dash_html = bob_dash.data.decode()
    assert "bob_private.txt" in bob_dash_html, "Bob should see his own file"
    assert "alice_document.txt" in bob_dash_html, "Bob should see alice's shared file"
    assert "alice_secret.txt" not in bob_dash_html, "Bob MUST NOT see alice's unshared secret file"
    print("  --> Bob's dashboard shows only his files and shared files; 'alice_secret.txt' is hidden.")

    # Bob attempts direct download of alice_secret.txt -> must 403
    bob_steal_resp = client.get(f"/files/{alice_secret_id}/download")
    assert bob_steal_resp.status_code == 403, f"Expected 403 for bob accessing unshared file, got {bob_steal_resp.status_code}"
    print("  --> Direct download attempt of unshared file by bob rejected with 403.")

    # 2. Admin check: alice's dashboard
    client.get("/auth/logout", follow_redirects=True)
    client.post("/auth/login", data={
        "identifier": "alice_admin",
        "password": "password123"
    }, follow_redirects=True)

    admin_dash = client.get("/files/")
    assert admin_dash.status_code == 200
    admin_dash_html = admin_dash.data.decode()
    assert "bob_private.txt" in admin_dash_html, "Admin must see bob's file"
    assert "alice_document.txt" in admin_dash_html, "Admin must see alice_document.txt"
    assert "alice_secret.txt" in admin_dash_html, "Admin must see alice_secret.txt"
    print("  --> Admin dashboard shows all files across all users.")

    # Admin downloads bob's file -> must succeed
    admin_dl_resp = client.get(f"/files/{bob_file_id}/download")
    assert admin_dl_resp.status_code == 200, f"Expected 200 for admin downloading bob's file, got {admin_dl_resp.status_code}"
    assert admin_dl_resp.data == bob_content, "Admin downloaded bob's file content match failed"
    print("  --> Admin successfully downloaded bob's file directly.")

    # Admin deletes bob's file -> must succeed
    admin_del_resp = client.post(f"/files/{bob_file_id}/delete", follow_redirects=True)
    assert admin_del_resp.status_code == 200
    with app.app_context():
        deleted_rec = db.session.get(FileRecord, bob_file_id)
        assert deleted_rec is None, "bob_private.txt record should be deleted from DB"
        bob_disk_file = Path(app.config["UPLOAD_DIR"]) / bob_record.stored_filename
        assert not bob_disk_file.exists(), "bob_private.txt file should be deleted from disk"
    print("  --> Admin successfully deleted bob's file from both DB and disk.")
    print("  [PASS] Test 5g passed successfully.")

    print("\n" + "=" * 70)
    print("ALL FUNCTIONAL TESTS (5a - 5g) PASSED WITH ZERO FLAWS!")
    print("=" * 70)


if __name__ == "__main__":
    run_tests()
