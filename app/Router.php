<?php

namespace App;

class Router
{
    private array $routes = [];

    public function get(string $path, callable $handler): void
    {
        $this->routes['GET'][$path] = $handler;
    }

    public function post(string $path, callable $handler): void
    {
        $this->routes['POST'][$path] = $handler;
    }

    public function dispatch(): void
    {
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

        if ($method === 'OPTIONS') {
            http_response_code(204);
            exit;
        }

        $uri = isset($_SERVER['PATH_INFO']) ? $_SERVER['PATH_INFO'] : '/';
        $uri = '/' . ltrim(rtrim($uri, '/'), '/');
        if ($uri === '') $uri = '/';

        if (isset($this->routes[$method][$uri])) {
            $params = $method === 'GET' ? $_GET : $this->parseBody();
            ($this->routes[$method][$uri])($params);
            return;
        }

        $this->notFound($method, $uri);
    }

    private function parseBody(): array
    {
        $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
        if (str_contains($contentType, 'application/json')) {
            $data = json_decode(file_get_contents('php://input'), true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                http_response_code(400);
                header('Content-Type: application/json');
                echo json_encode(['success' => false, 'error' => ['code' => 400, 'message' => 'JSON inválido.']]);
                exit;
            }
            return $data ?? [];
        }
        return $_POST;
    }

    private function notFound(string $method, string $uri): void
    {
        $methodExists = false;
        foreach ($this->routes as $m => $paths) {
            if ($m !== $method && isset($paths[$uri])) {
                $methodExists = true;
                break;
            }
        }
        $status  = $methodExists ? 405 : 404;
        $message = $methodExists
            ? "Método {$method} no permitido para {$uri}."
            : "Ruta {$uri} no encontrada.";

        http_response_code($status);
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'error' => ['code' => $status, 'message' => $message]]);
        exit;
    }
}