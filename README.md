# Лабораторная работа №1 — Разработка защищённого REST API

## Описание проекта
получить практический опыт разработки безопасного backend-приложения с автоматизированной проверкой кода на уязвимости. Освоить принципы защиты от OWASP Top 10 и интеграцию инструментов безопасности в процесс разработки.

## API — доступные эндпоинты

### POST `/register`

**Описание:** регистрация нового пользователя.

Пример запроса:

```json
{
  "username": "admin",
  "password": "123456789"
}
```

Пример ответа (`201 Created`):

```json
{
  "id": 1,
  "username": "testuser123"
}
```


### POST `/auth/login`

**Описание:** вход пользователя и получение JWT-токена для последующего доступа к защищённым эндпоинтам.

Пример запроса:

```json
{
  "username": "admin",
  "password": "123456789"
}
```

Пример ответа (`200 OK`):

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

При неверном имени пользователя или пароле возвращается `401 Unauthorized`.

### GET `/api/data`

**Описание:** получение защищённых данных для авторизованных пользователей.

Заголовок запроса:

```http
Authorization: Bearer <access_token>
```

Пример ответа (`200 OK`):

```json
{
  "message": "Authenticated access granted",
  "requested_by": "admin",
  "items": [
    {
      "id": 1,
      "title": "Security basics"
    },
    {
      "id": 2,
      "title": "REST API protection"
    }
  ]
}
```

Если JWT-токен отсутствует, недействителен или просрочен, доступ к защищённому ресурсу отклоняется.

### GET `/me`

**Описание:** получение информации о текущем авторизованном пользователе.

Заголовок запроса:

```http
Authorization: Bearer <access_token>
```

Пример ответа (`200 OK`):

```json
{
  "id": 1,
  "username": "admin"
}
```

Информация о пользователе определяется на основе проверенного JWT-токена. Клиент не может самостоятельно указать идентификатор пользователя в качестве источника доверенной личности.

## Реализованные меры защиты

### 1. Защита от SQL Injection

Для работы с базой данных используется SQLite с параметризованными SQL-запросами.

Пример поиска пользователя при аутентификации:

```python
cursor = db.execute(
    """
    INSERT INTO users (username, password_hash)
    VALUES (?, ?)
    """,
    (user.username, hashed_password),
)
```

Пользовательские данные передаются отдельно от SQL-команды, а не объединяются со строкой запроса. Это снижает риск SQL Injection.

При регистрации также используется параметризованный запрос:

```python
user = db.execute(
    """
    SELECT id, username, password_hash
    FROM users
    WHERE username = ?
    """,
    (credentials.username,),
).fetchone()
```

### 2. Защита от XSS (Cross-Site Scripting)

API возвращает данные в формате JSON и не формирует HTML-страницы из пользовательского ввода.

Для имени пользователя применяется валидация: разрешены только латинские буквы, цифры и символ `_`. Поэтому строка вида `<script>alert(1)</script>` отклоняется на этапе проверки входных данных.

Для контекстного экранирования HTML-символов предусмотрена функция `escape_html()`:

```python
from html import escape

def escape_html(value: str) -> str:
    """Escape HTML-sensitive characters in untrusted text."""
    return escape(value, quote=True)
```

```python
return UserResponse(
    id=cursor.lastrowid,
    username=escape_html(user.username),
)
```


### 3. Безопасная аутентификация и хранение паролей 

Этот код отвечает за проверку пароля.
```python
if user is None or not password_hash.verify(
    credentials.password, user["password_hash"]
):
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )
```

Отвечает за создание JWT-токенов доступа
```python
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
):
```