# tests/unit/test_main.py
from fastapi.testclient import TestClient
from uuid import uuid4
from datetime import datetime
from app.main import app
from app.database import get_db
from unittest.mock import patch, MagicMock
from app.auth.dependencies import get_current_active_user
from datetime import datetime, timezone, timedelta


client = TestClient(app)

def test_create_calculation_success():
    mock_user = MagicMock()
    mock_user.id = uuid4()   # must be UUID

    # Build a valid fake Calculation object
    class FakeCalculation:
        id = uuid4()
        user_id = mock_user.id
        type = "addition"
        inputs = [40, 2]
        result = 42
        created_at = datetime.utcnow()
        updated_at = datetime.utcnow()

        def get_result(self):
            return self.result

    fake_calc_instance = FakeCalculation()
    mock_db = MagicMock()

    # Override dependencies
    app.dependency_overrides = {}
    app.dependency_overrides[get_current_active_user] = lambda: mock_user
    app.dependency_overrides[get_db] = lambda: mock_db

    with patch("app.main.Calculation.create", return_value=fake_calc_instance):

        response = client.post(
            "/calculations",
            json={"type": "addition", "inputs": [40, 2]}
        )

    assert response.status_code == 201
    data = response.json()
    assert data["result"] == 42
    assert data["type"] == "addition"
    assert data["inputs"] == [40, 2]


def test_create_calculation_value_error():
    mock_user = MagicMock()
    mock_user.id = "user-123"

    mock_db = MagicMock()

    app.dependency_overrides = {}
    app.dependency_overrides[get_current_active_user] = lambda: mock_user
    app.dependency_overrides[get_db] = lambda: mock_db

    with patch("app.main.Calculation.create", side_effect=ValueError("Invalid")):

        response = client.post(
            "/calculations",
            json={"type": "addition", "inputs": [1, 2]}
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid"
    mock_db.rollback.assert_called_once()


def test_health_endpoint():
    """Ensure /health returns expected JSON."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_home_page():
    """Ensure the home page loads (template rendering)."""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_login_page():
    response = client.get("/login")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_register_page():
    response = client.get("/register")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_dashboard_page_requires_no_token_but_still_renders():
    """
    NOTE: dashboard template loads even without auth
    because the FRONTEND JS handles redirect logic.
    The HTML endpoint ALWAYS renders.
    """
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


# ------------------------------------------------------
# 1. SUCCESSFUL UPDATE
# ------------------------------------------------------
def test_update_calculation_success():
    calc_id = uuid4()

    mock_user = MagicMock()
    mock_user.id = uuid4()

    # Existing calculation in DB
    class FakeCalculation:
        id = calc_id
        user_id = mock_user.id
        type = "addition"
        inputs = [10, 2]
        result = 12
        created_at = datetime.utcnow()
        updated_at = datetime.utcnow()

        def get_result(self):
            return sum(self.inputs)

    fake_calc_obj = FakeCalculation()
    mock_db = MagicMock()

    # Simulate query result
    mock_db.query().filter().first.return_value = fake_calc_obj

    # Override dependencies
    app.dependency_overrides = {}
    app.dependency_overrides[get_current_active_user] = lambda: mock_user
    app.dependency_overrides[get_db] = lambda: mock_db

    response = client.put(
        f"/calculations/{calc_id}",
        json={"inputs": [40, 2]}   # new inputs
    )

    assert response.status_code == 200
    data = response.json()
    assert data["inputs"] == [40, 2]
    assert data["result"] == 42


# ------------------------------------------------------
# 2. INVALID UUID → 400
# ------------------------------------------------------
def test_update_calculation_invalid_uuid():
    mock_user = MagicMock()
    mock_user.id = uuid4()
    mock_db = MagicMock()

    app.dependency_overrides = {}
    app.dependency_overrides[get_current_active_user] = lambda: mock_user
    app.dependency_overrides[get_db] = lambda: mock_db

    response = client.put(
        "/calculations/not-a-uuid",
        json={"inputs": [40, 2]}
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid calculation id format."


# ------------------------------------------------------
# 3. CALCULATION NOT FOUND → 404
# ------------------------------------------------------
def test_update_calculation_not_found():
    calc_id = uuid4()

    mock_user = MagicMock()
    mock_user.id = uuid4()
    mock_db = MagicMock()

    # Query returns None
    mock_db.query().filter().first.return_value = None

    app.dependency_overrides = {}
    app.dependency_overrides[get_current_active_user] = lambda: mock_user
    app.dependency_overrides[get_db] = lambda: mock_db

    response = client.put(
        f"/calculations/{calc_id}",
        json={"inputs": [10, 5]}
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Calculation not found."

# ------------------------------------------------------
# 4. SUCCESSFUL LOGIN USING FORM DATA
# ------------------------------------------------------
def test_login_form_success():
    mock_db = MagicMock()

    # Mocked authentication result
    mock_auth_result = {
        "access_token": "fake-token-123",
        "token_type": "bearer",
        "user": MagicMock()
    }

    app.dependency_overrides = {}
    app.dependency_overrides[get_db] = lambda: mock_db

    # Patch User.authenticate to return success
    with patch("app.main.User.authenticate", return_value=mock_auth_result):
        response = client.post(
            "/auth/token",
            data={"username": "testuser", "password": "testpass"},
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        assert response.status_code == 200
        data = response.json()

        assert data["access_token"] == "fake-token-123"
        assert data["token_type"] == "bearer"


# ------------------------------------------------------
# 2. FAILED LOGIN (INVALID CREDENTIALS)
# ------------------------------------------------------
def test_login_json_invalid_credentials():
    mock_db = MagicMock()

    # FIX: proper override that yields a DB session
    def override_get_db():
        yield mock_db

    app.dependency_overrides = {}
    app.dependency_overrides[get_db] = override_get_db

    with patch("app.main.User.authenticate", return_value=None):
        response = client.post(
            "/auth/login",
            json={"username": "wrong", "password": "badpass"}
        )

        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid username or password"



# ------------------------------------------------------
# 3. ENSURE authenticate() IS CALLED WITH CORRECT ARGUMENTS
# ------------------------------------------------------
def test_login_form_calls_authenticate_correctly():
    mock_db = MagicMock()

    app.dependency_overrides = {}
    app.dependency_overrides[get_db] = lambda: mock_db

    with patch("app.main.User.authenticate", return_value=None) as mock_auth:
        client.post(
            "/auth/token",
            data={"username": "abc", "password": "123"},
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        # Ensure authenticate was called once with username + password
        mock_auth.assert_called_once()
        called_user, called_pass = mock_auth.call_args[0][1:3]

        assert called_user == "abc"
        assert called_pass == "123"

# ------------------------------------------------------
# 4. SUCCESSFUL JSON LOGIN
# ------------------------------------------------------
def test_login_json_success():
    mock_db = MagicMock()

    mock_user = MagicMock()
    mock_user.id = uuid4()
    mock_user.username = "testuser"
    mock_user.email = "test@example.com"
    mock_user.first_name = "John"
    mock_user.last_name = "Doe"
    mock_user.is_active = True
    mock_user.is_verified = True

    expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

    mock_auth_result = {
        "access_token": "token123",
        "refresh_token": "refresh123",
        "user": mock_user,
        "expires_at": expires_at
    }

    # Dependency overrides
    app.dependency_overrides = {}
    app.dependency_overrides[get_db] = lambda: mock_db

    with patch("app.main.User.authenticate", return_value=mock_auth_result):
        response = client.post(
            "/auth/login",
            json={"username": "testuser", "password": "password123"}
        )

        assert response.status_code == 200
        data = response.json()

        # Tokens returned
        assert data["access_token"] == "token123"
        assert data["refresh_token"] == "refresh123"
        assert data["token_type"] == "bearer"

        # User fields returned
        assert data["user_id"] == str(mock_user.id)
        assert data["username"] == "testuser"
        assert data["email"] == "test@example.com"
        assert data["first_name"] == "John"
        assert data["last_name"] == "Doe"
        assert data["is_active"] is True
        assert data["is_verified"] is True


# ------------------------------------------------------
# 5. FAILED LOGIN (INVALID CREDENTIALS)
# ------------------------------------------------------
def test_login_json_invalid_credentials():
    mock_db = MagicMock()

    def override_get_db():
        yield mock_db

    app.dependency_overrides = {}
    app.dependency_overrides[get_db] = override_get_db

    with patch("app.main.User.authenticate", return_value=None):
        response = client.post(
            "/auth/login",
            json={"username": "wrong", "password": "badpass1"}  # FIXED
        )

        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid username or password"



# ------------------------------------------------------
# 6. ENSURE authenticate() IS CALLED CORRECTLY
# ------------------------------------------------------
def test_login_json_calls_authenticate():
    mock_db = MagicMock()

    def override_get_db():
        yield mock_db

    app.dependency_overrides = {}
    app.dependency_overrides[get_db] = override_get_db

    with patch("app.main.User.authenticate", return_value=None) as mock_auth:

        client.post(
            "/auth/login",
            json={"username": "abc", "password": "12345678"}  # FIXED
        )

        # Ensure authenticate was called once
        mock_auth.assert_called_once()

# ------------------------------------------------------
# 7. SUCCESSFUL DELETE → 204
# ------------------------------------------------------
def test_delete_calculation_success():
    calc_id = uuid4()

    mock_user = MagicMock()
    mock_user.id = uuid4()

    # Fake calculation object
    class FakeCalculation:
        id = calc_id
        user_id = mock_user.id
        type = "addition"
        inputs = [1, 2]
        result = 3
        created_at = datetime.utcnow()
        updated_at = datetime.utcnow()

    fake_calc_obj = FakeCalculation()
    mock_db = MagicMock()

    # Simulate DB returning the calculation
    mock_db.query().filter().first.return_value = fake_calc_obj

    # Dependency overrides
    def override_db():
        yield mock_db

    app.dependency_overrides = {}
    app.dependency_overrides[get_current_active_user] = lambda: mock_user
    app.dependency_overrides[get_db] = override_db

    response = client.delete(f"/calculations/{calc_id}")

    assert response.status_code == 204
    mock_db.delete.assert_called_once_with(fake_calc_obj)
    mock_db.commit.assert_called_once()


# ------------------------------------------------------
# 8. INVALID UUID → 400 BAD REQUEST
# ------------------------------------------------------
def test_delete_calculation_invalid_uuid():
    mock_user = MagicMock()
    mock_user.id = uuid4()
    mock_db = MagicMock()

    def override_db():
        yield mock_db

    app.dependency_overrides = {}
    app.dependency_overrides[get_current_active_user] = lambda: mock_user
    app.dependency_overrides[get_db] = override_db

    response = client.delete("/calculations/not-a-valid-uuid")

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid calculation id format."


# ------------------------------------------------------
# 9. CALCULATION NOT FOUND → 404
# ------------------------------------------------------
def test_delete_calculation_not_found():
    calc_id = uuid4()

    mock_user = MagicMock()
    mock_user.id = uuid4()
    mock_db = MagicMock()

    # DB returns None → calculation does not exist
    mock_db.query().filter().first.return_value = None

    def override_db():
        yield mock_db

    app.dependency_overrides = {}
    app.dependency_overrides[get_current_active_user] = lambda: mock_user
    app.dependency_overrides[get_db] = override_db

    response = client.delete(f"/calculations/{calc_id}")

    assert response.status_code == 404
    assert response.json()["detail"] == "Calculation not found."


# ---------------------------------------------
# 10. SUCCESSFUL REGISTRATION → 201 CREATED
# ---------------------------------------------
def test_register_success():
    mock_db = MagicMock()

    # Fake user object returned by User.register
    class FakeUser:
        id = uuid4()
        username = "newuser"
        email = "new@example.com"
        first_name = "John"
        last_name = "Doe"
        is_active = True
        is_verified = True
        created_at = datetime.utcnow()
        updated_at = datetime.utcnow()

    fake_user_obj = FakeUser()

    # Override DB dependency
    def override_db():
        yield mock_db

    app.dependency_overrides = {}
    app.dependency_overrides[get_db] = override_db

    with patch("app.main.User.register", return_value=fake_user_obj) as mock_register:

        response = client.post(
            "/auth/register",
            json={
                "username": "newuser",
                "email": "new@example.com",
                "first_name": "John",
                "last_name": "Doe",
                "password": "StrongPass123!",
                "confirm_password": "StrongPass123!",
            }
        )

        assert response.status_code == 201
        data = response.json()

        # Check returned structure
        assert data["username"] == "newuser"
        assert data["email"] == "new@example.com"
        assert data["first_name"] == "John"

        # Confirm DB methods were called
        mock_db.commit.assert_called_once()
        mock_db.refresh.assert_called_once_with(fake_user_obj)

        # Ensure confirm_password was removed
        args, kwargs = mock_register.call_args
        passed_data = args[1]
        assert "confirm_password" not in passed_data


# --------------------------------------------------------
# 11. REGISTRATION FAILS → User.register raises ValueError
# --------------------------------------------------------
def test_register_value_error():
    mock_db = MagicMock()

    def override_db():
        yield mock_db

    app.dependency_overrides = {}
    app.dependency_overrides[get_db] = override_db

    # Simulate ValueError in User.register
    with patch("app.main.User.register", side_effect=ValueError("username taken")):

        response = client.post(
            "/auth/register",
            json={
                "username": "existinguser",
                "email": "existing@example.com",
                "first_name": "John",
                "last_name": "Doe",
                "password": "StrongPass123!",
                "confirm_password": "StrongPass123!",
            }
        )

        assert response.status_code == 400
        assert response.json()["detail"] == "username taken"

        mock_db.rollback.assert_called_once()


# -------------------------------------------------------------------
# 12. ENSURE User.register IS CALLED WITH CONFIRM_PASSWORD REMOVED
# -------------------------------------------------------------------
def test_register_excludes_confirm_password():
    mock_db = MagicMock()

    def override_db():
        yield mock_db

    app.dependency_overrides = {}
    app.dependency_overrides[get_db] = override_db

    # Fake user with valid fields
    class FakeUser:
        id = uuid4()
        username = "abc"
        email = "abc@example.com"
        first_name = "A"
        last_name = "B"
        is_active = True
        is_verified = True
        created_at = datetime.utcnow()
        updated_at = datetime.utcnow()

    fake_user = FakeUser()

    with patch("app.main.User.register", return_value=fake_user) as mock_register:

        response = client.post(
            "/auth/register",
            json={
                "username": "abc",
                "email": "abc@example.com",
                "first_name": "A",
                "last_name": "B",
                "password": "Password123!",
                "confirm_password": "Password123!"
            }
        )

        assert response.status_code == 201

        # Ensure confirm_password was removed before calling User.register
        args, kwargs = mock_register.call_args
        passed_data = args[1]

        assert "confirm_password" not in passed_data
        assert passed_data["username"] == "abc"
        assert passed_data["email"] == "abc@example.com"
