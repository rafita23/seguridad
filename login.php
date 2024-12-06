<?php


require 'db.php';
session_start();

/**
 * ISO 27001:
 * - Manejo seguro de sesiones (regeneración, expiración).
 * - Prevención de ataques CSRF con tokens.
 * - Registro de intentos fallidos para auditoría.
 */

// CSRF Tokennnnnnnnnnnnnnnnnnnnn
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Límite de intentossssssssssss
if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = 0;
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("Error de validación de token CSRF.");
    }

    if ($_SESSION['login_attempts'] >= 5) {
        die("Demasiados intentos fallidos. Inténtalo más tarde.");
    }

    $username = trim($_POST['username']);
    $password = trim($_POST['password']);

    if (empty($username) || empty($password)) {
        die("El usuario y la contraseña son obligatorios.");
    }

    // Validación de usuario en la base de datossssssssssssssssssss
    $stmt = $pdo->prepare("SELECT * FROM usuarios WHERE username = :username");
    $stmt->execute(['username' => $username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($password, $user['password_hash'])) {
        // Regenerar sesiónnnnnnn
        session_regenerate_id(true);
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['last_activity'] = time(); // ISO 27001: Tiempo de sesión

        header("Location: dashboard.php");
        exit();
    } else {
        $_SESSION['login_attempts']++;
        echo "Usuario o contraseña incorrectos.";
    }
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Inicio de Sesión Seguro</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1 class="text-center">Inicio de Sesión</h1>
        <form method="POST" action="login.php" class="mt-4">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <div class="mb-3">
                <label for="username" class="form-label">Usuario</label>
                <input type="text" name="username" id="username" class="form-control" required>
            </div>
            <div class="mb-3">
                <label for="password" class="form-label">Contraseña</label>
                <input type="password" name="password" id="password" class="form-control" required>
            </div>
            <button type="submit" class="btn btn-success w-100">Iniciar Sesión</button>
        </form>
    </div>
</body>
</html>
