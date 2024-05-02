# REST API для работы с пользователями

Это простой REST API, написанный на PHP с использованием базы данных MySQL, для работы с пользователями. API предоставляет методы для создания, обновления, удаления, аутентификации и получения информации о пользователях.

## Методы API

### Создание пользователя

**URL:** `/api/users/create`

**Метод:** POST

**Описание:** Этот метод создает нового пользователя с указанными данными.

**Параметры запроса:**
- `username` (string, обязательный) - имя пользователя
- `email` (string, обязательный) - адрес электронной почты пользователя
- `password` (string, обязательный) - пароль пользователя




### Обновление информации о пользователе

**URL:** `/api/users/update`

**Метод:** PUT

**Описание:** Этот метод обновляет информацию о существующем пользователе.

**Параметры запроса:**
- `userId` (integer, обязательный) - идентификатор пользователя
- `newUsername` (string, обязательный) - новое имя пользователя
- `newEmail` (string, обязательный) - новый адрес электронной почты пользователя




### Удаление пользователя

**URL:** `/api/users/delete`

**Метод:** DELETE

**Описание:** Этот метод удаляет пользователя по его идентификатору.

**Параметры запроса:**
- `userId` (integer, обязательный) - идентификатор пользователя




### Получение информации о пользователе

**URL:** `/api/users/info`

**Метод:** GET

**Описание:** Этот метод возвращает информацию о пользователе по его идентификатору.

**Параметры запроса:**
- `userId` (integer, обязательный) - идентификатор пользователя




