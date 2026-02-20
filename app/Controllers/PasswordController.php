<?php

namespace App\Controllers;

use App\Services\PasswordGenerator;
use App\Validators\PasswordRequestValidator;

/**
 * PasswordController
 * Maneja todos los endpoints de la API REST de contraseñas.
 */
class PasswordController
{
    public function __construct(
        private readonly PasswordGenerator         $generator,
        private readonly PasswordRequestValidator  $validator
    ) {}

    public function generate(array $params): void
    {
        try {
            $opts = $this->validator->validateSingle($params);

            $password = $this->generator->generate(
                length:           $opts['length'],
                upper:            $opts['includeUppercase'],
                lower:            $opts['includeLowercase'],
                digits:           $opts['includeNumbers'],
                symbols:          $opts['includeSymbols'],
                excludeAmbiguous: $opts['excludeAmbiguous'],
                exclude:          $opts['excludeChars'],
                requireEach:      $opts['requireEach'],
            );

            $this->json([
                'success'  => true,
                'password' => $password,
                'options'  => $opts,
            ], 200);

        } catch (\InvalidArgumentException $e) {
            $this->error($e->getMessage(), 400);
        } catch (\Throwable $e) {
            $this->error('Error interno del servidor.', 500);
        }
    }

    public function generateMany(array $body): void
    {
        try {
            $opts = $this->validator->validateMany($body);

            $passwords = $this->generator->generateMany(
                count:            $opts['count'],
                length:           $opts['length'],
                upper:            $opts['includeUppercase'],
                lower:            $opts['includeLowercase'],
                digits:           $opts['includeNumbers'],
                symbols:          $opts['includeSymbols'],
                excludeAmbiguous: $opts['excludeAmbiguous'],
                exclude:          $opts['excludeChars'],
                requireEach:      $opts['requireEach'],
            );

            $this->json([
                'success'   => true,
                'count'     => count($passwords),
                'passwords' => $passwords,
                'options'   => $opts,
            ], 201);

        } catch (\InvalidArgumentException $e) {
            $this->error($e->getMessage(), 400);
        } catch (\Throwable $e) {
            $this->error('Error interno del servidor.', 500);
        }
    }

    public function validatePassword(array $body): void
    {
        try {
            if (empty($body['password']) || !is_string($body['password'])) {
                throw new \InvalidArgumentException('El campo "password" es requerido y debe ser una cadena.');
            }

            $requirements = $body['requirements'] ?? [];
            $result = $this->generator->validate($body['password'], $requirements);

            $this->json([
                'success' => true,
                'result'  => $result,
            ], 200);

        } catch (\InvalidArgumentException $e) {
            $this->error($e->getMessage(), 400);
        } catch (\Throwable $e) {
            $this->error('Error interno del servidor.', 500);
        }
    }

    private function json(array $data, int $status = 200): void
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        exit;
    }

    private function error(string $message, int $status): void
    {
        $this->json([
            'success' => false,
            'error'   => [
                'code'    => $status,
                'message' => $message,
            ],
        ], $status);
    }
}
