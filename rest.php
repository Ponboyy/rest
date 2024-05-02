<?php
// Подключение к базе данных
$host = "localhost";
$dbname = "rest";
$username = "root";
$password = "";

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    // Обработка ошибки подключения к базе данных
    sendResponse("error", "Database connection failed");
}

// Функция для отправки ответа в формате JSON
function sendResponse($status, $message, $data = null) {
    header("Content-Type: application/json");
    echo json_encode(array("status" => $status, "message" => $message, "data" => $data));
    exit;
}

// Метод создания пользователя
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_SERVER['REQUEST_URI'] === '/api/users/create') {
    
    $data = json_decode(file_get_contents("php://input"), true);

    // Проверка наличия обязательных полей в данных
    if (!isset($data['username']) || !isset($data['email']) || !isset($data['password'])) {
        sendResponse("error", "Missing required fields");
    }

    // Проверка корректности email адреса
    if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
        sendResponse("error", "Invalid email format");
    }

    $username = htmlspecialchars($data['username']);
    $email = htmlspecialchars($data['email']);
    $password = password_hash($data['password'], PASSWORD_DEFAULT);

    try {
        $stmt = $pdo->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
        $stmt->execute([$username, $email, $password]);
        sendResponse("success", "User created successfully");
    } catch (PDOException $e) {
        // Обработка ошибки добавления пользователя в базу данных
        sendResponse("error", "Failed to create user");
    }
}

// Метод обновления информации о пользователе
if ($_SERVER['REQUEST_METHOD'] === 'PUT' && $_SERVER['REQUEST_URI'] === '/api/users/update') {
    
    $data = json_decode(file_get_contents("php://input"), true);

    // Проверка наличия обязательных полей в данных
    if (!isset($data['userId']) || !isset($data['newUsername']) || !isset($data['newEmail'])) {
        sendResponse("error", "Missing required fields");
    }

    // Проверка корректности email адреса
    if (!filter_var($data['newEmail'], FILTER_VALIDATE_EMAIL)) {
        sendResponse("error", "Invalid email format");
    }

    $userId = $data['userId'];
    $newUsername = htmlspecialchars($data['newUsername']);
    $newEmail = htmlspecialchars($data['newEmail']);

    try {
        $stmt = $pdo->prepare("UPDATE users SET username = ?, email = ? WHERE id = ?");
        $stmt->execute([$newUsername, $newEmail, $userId]);
        sendResponse("success", "User information updated successfully");
    } catch (PDOException $e) {
        // Обработка ошибки обновления информации о пользователе
        sendResponse("error", "Failed to update user information");
    }
}

// Метод удаления пользователя
if ($_SERVER['REQUEST_METHOD'] === 'DELETE' && $_SERVER['REQUEST_URI'] === '/api/users/delete') {
    
    $data = json_decode(file_get_contents("php://input"), true);

    // Проверка наличия обязательных полей в данных
    if (!isset($data['userId'])) {
        sendResponse("error", "Missing required fields");
    }

    $userId = $data['userId'];

    try {
        $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        sendResponse("success", "User deleted successfully");
    } catch (PDOException $e) {
        // Обработка ошибки удаления пользователя
        sendResponse("error", "Failed to delete user");
    }
}

// Метод аутентификации пользователя
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_SERVER['REQUEST_URI'] === '/api/users/login') {
    
    $data = json_decode(file_get_contents("php://input"), true);

    // Проверка наличия обязательных полей в данных
    if (!isset($data['email']) || !isset($data['password'])) {
        sendResponse("error", "Missing required fields");
    }

    $email = htmlspecialchars($data['email']);
    $password = $data['password'];

    try {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            // Пользователь аутентифицирован успешно
            sendResponse("success", "User authenticated successfully", array("userId" => $user['id']));
        } else {
            // Неверный email или пароль
            sendResponse("error", "Invalid email or password");
        }
    } catch (PDOException $e) {
        // Обработка ошибки аутентификации пользователя
        sendResponse("error", "Failed to authenticate user");
    }
}

// Метод получения информации о пользователе
if ($_SERVER['REQUEST_METHOD'] === 'GET' && $_SERVER['REQUEST_URI'] === '/api/users/info') {
    
    $data = json_decode(file_get_contents("php://input"), true);

    // Проверка наличия обязательных полей в данных
    if (!isset($data['userId'])) {
        sendResponse("error", "Missing required fields");
    }

    $userId = $data['userId'];

    try {
        $stmt = $pdo->prepare("SELECT id, username, email FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            sendResponse("success", "User information retrieved successfully", $user);
        } else {
            sendResponse("error", "User not found");
        }
    } catch (PDOException $e) {
        // Обработка ошибки получения информации о пользователе
        sendResponse("error", "Failed to retrieve user information");
    }
}

// Если запрос не соответствует ни одному из методов, отправляем ошибку
sendResponse("error", "Invalid request method or URL");
?>
