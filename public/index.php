<?php

declare(strict_types=1);

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Accept');

spl_autoload_register(function (string $class): void {
    $base = __DIR__ . '/../';
    $file = $base . str_replace(['App\\', '\\'], ['app/', '/'], $class) . '.php';

    if (file_exists($file)) {
        require_once $file;
    }
});

use App\Router;

$router = new Router();

require_once __DIR__ . '/../routes/api.php';

$router->dispatch();
