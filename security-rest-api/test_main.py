
import os

# 测试前设置独立的测试密钥
os.environ["JWT_SECRET"] = "test-only-secret-key-not-for-production"

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_register_and_login_and_me():
    # 每次测试使用不同用户名，避免重复注册冲突
    import uuid

    username = "test_" + uuid.uuid4().hex[:12]
    password = "TestPassword123!"

    # 注册用户
    register_response = client.post(
        "/register",
        json={"username": username, "password": password},
    )
    assert register_response.status_code == 201
    assert register_response.json()["username"] == username

    # 使用正确密码登录
    login_response = client.post(
        "/auth/login",
        json={"username": username, "password": password},
    )
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    assert token

    # 不带 Token 访问 /me，应该被拒绝
    unauthorized_response = client.get("/me")
    assert unauthorized_response.status_code in (401, 403)

    # 带有效 Token 访问 /me
    me_response = client.get(
        "/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_response.status_code == 200
    assert me_response.json()["username"] == username


def test_wrong_password_is_rejected():
    response = client.post(
        "/auth/login",
        json={
            "username": "user_that_does_not_exist",
            "password": "WrongPassword123!",
        },
    )
    assert response.status_code == 401


def test_duplicate_username_is_rejected():
    import uuid

    username = "dup_" + uuid.uuid4().hex[:12]
    password = "TestPassword123!"

    first = client.post(
        "/register",
        json={"username": username, "password": password},
    )
    assert first.status_code == 201

    second = client.post(
        "/register",
        json={"username": username, "password": password},
    )
    assert second.status_code == 409

def test_api_data_requires_authentication():
    # 不带 Token 应该被拒绝
    response = client.get("/api/data")
    assert response.status_code in (401, 403)


def test_api_data_with_token():
    import uuid

    username = "api_" + uuid.uuid4().hex[:12]
    password = "TestPassword123!"

    client.post(
        "/register",
        json={"username": username, "password": password},
    )

    login_response = client.post(
        "/auth/login",
        json={"username": username, "password": password},
    )
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    response = client.get(
        "/api/data",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["requested_by"] == username
    assert len(response.json()["items"]) == 2
