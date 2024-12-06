<?php

require 'db.php';

/**
 * ISO 27001: Se asegura el manejo seguro de contraseñas mediante:
 * 1. Encriptación fuerte con `password_hash` (BCRYPT).
 * 2. Validación de entradas para prevenir vulnerabilidades como inyección de datos.
 * 3. Uso de conexiones seguras y prácticas seguras en base de datos.
 */

// para prevenir XSS
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';");

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = trim($_POST['username']);
    $password = trim($_POST['password']);
    $confirm_password = trim($_POST['confirm_password']);

    // Sanitizar entrada
    $username = htmlspecialchars($username);

    if (empty($username) || empty($password) || empty($confirm_password)) {
        die("Todos los campos son obligatorios.");
    }

    if ($password !== $confirm_password) {
        die("Las contraseñas no coinciden.");
    }

    // ISO 27001: Recomendamos contraseñas fuertes (mín. 8 caracteres, combinaciones de números, letras y símbolos).
    if (strlen($password) < 8 || !preg_match('/[0-9]/', $password) || !preg_match('/[!@#$%^&*]/', $password)) {
        die("La contraseña debe tener al menos 8 caracteres, incluyendo números y símbolos.");
    }

    // vaaaaaalidar duplicidad de usuario
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM usuarios WHERE username = :username");
    $stmt->execute(['username' => $username]);
    if ($stmt->fetchColumn() > 0) {
        die("El usuario ya existe. Elija otro nombre de usuario.");
    }

    // eeeeeeeeeeeeeeeeencriptar la contraseña usando password_hash
    $password_hash = password_hash($password, PASSWORD_BCRYPT);

    // Insertar usuario en la base de datos
    try {
        $stmt = $pdo->prepare("INSERT INTO usuarios (username, password_hash) VALUES (:username, :password_hash)");
        $stmt->execute(['username' => $username, 'password_hash' => $password_hash]);
        echo "Registro exitoso.";
    } catch (PDOException $e) {
        // Mensaje de errorrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr genérico
        error_log("Error en registro: " . $e->getMessage()); // ISO 27001: Registro de errores en lugar seguro
        die("Hubo un problema al registrar al usuario. Inténtalo de nuevo.");
    }
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registro de Usuario</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1 class="text-center">Registro de Usuario</h1>
        <form method="POST" action="register.php" class="mt-4">
            <div class="mb-3">
                <label for="username" class="form-label">Usuario</label>
                <input type="text" name="username" id="username" class="form-control" required>
            </div>
            <div class="mb-3">
                <label for="password" class="form-label">Contraseña</label>
                <input type="password" name="password" id="password" class="form-control" required>
            </div>
            <div class="mb-3">
                <label for="confirm_password" class="form-label">Confirmar Contraseña</label>
                <input type="password" name="confirm_password" id="confirm_password" class="form-control" required>
            </div>
            <button type="submit" class="btn btn-primary w-100">Registrar</button>
        </form>
    </div>
</body>
</html>
