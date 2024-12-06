<?php
session_start();

/**
 * ISO 27001:
 * - Validación de sesión segura.
 * - Expiración automática por inactividad.
 */

// Expiración de sesión por inactividaddddd esto inge me llamó la antenc
$timeout_duration = 600; // 10 minutos
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $timeout_duration) {
    session_unset();
    session_destroy();
    header("Location: login.php");
    exit();
}

$_SESSION['last_activity'] = time();

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1 class="text-center">Bienvenido al Sistema Seguro</h1>
        <a href="logout.php" class="btn btn-danger mt-3">Cerrar Sesión</a>
    </div>
</body>
</html>
