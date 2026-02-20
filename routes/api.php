<?php

use App\Router;
use App\Controllers\PasswordController;
use App\Services\PasswordGenerator;
use App\Validators\PasswordRequestValidator;

$generator  = new PasswordGenerator();
$validator  = new PasswordRequestValidator();
$controller = new PasswordController($generator, $validator);

// GET /api/password  – genera una contrasenna
$router->get('/api/password', fn(array $p) => $controller->generate($p));

// POST /api/passwords – genera múltiples contrasennas
$router->post('/api/passwords', fn(array $b) => $controller->generateMany($b));

// POST /api/password/validate – valida una contrasenna existente
$router->post('/api/password/validate', fn(array $b) => $controller->validatePassword($b));
