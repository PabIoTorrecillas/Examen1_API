<?php

namespace App\Validators;

use App\Services\PasswordGenerator;

/**
 * PasswordRequestValidator
 * Centraliza y normaliza la validación de los parámetros de entrada.
 */
class PasswordRequestValidator
{
    /**
     * Valida parámetros para generar una sola contraseña (GET /api/password).
     *
     * @param array $params $_GET
     * @return array Opciones normalizadas.
     */
    public function validateSingle(array $params): array
    {
        return $this->buildOptions($params);
    }

    /**
     * Valida el cuerpo para generar múltiples contraseñas (POST /api/passwords).
     *
     * @param array $body JSON body decodificado.
     * @return array Opciones normalizadas + count.
     */
    public function validateMany(array $body): array
    {
        $opts = $this->buildOptions($body);

        $count = isset($body['count']) ? (int) $body['count'] : 1;
        if ($count < 1 || $count > PasswordGenerator::MAX_COUNT) {
            throw new \InvalidArgumentException(
                sprintf('El parámetro "count" debe estar entre 1 y %d.', PasswordGenerator::MAX_COUNT)
            );
        }
        $opts['count'] = $count;

        return $opts;
    }

    // ──────────────────────────────────────────────────────────────
    // Privado
    // ──────────────────────────────────────────────────────────────

    private function buildOptions(array $input): array
    {
        // Longitud
        $length = isset($input['length']) ? (int) $input['length'] : 16;
        if ($length < PasswordGenerator::MIN_LENGTH || $length > PasswordGenerator::MAX_LENGTH) {
            throw new \InvalidArgumentException(
                sprintf(
                    'La longitud debe estar entre %d y %d caracteres. Recibido: %d.',
                    PasswordGenerator::MIN_LENGTH,
                    PasswordGenerator::MAX_LENGTH,
                    $length
                )
            );
        }

        // Booleanos (acepta true / "true" / 1 / "1")
        $toBool = fn($v, $default) => isset($v) ? filter_var($v, FILTER_VALIDATE_BOOLEAN) : $default;

        $includeUppercase  = $toBool($input['includeUppercase']  ?? null, true);
        $includeLowercase  = $toBool($input['includeLowercase']  ?? null, true);
        $includeNumbers    = $toBool($input['includeNumbers']    ?? null, true);
        $includeSymbols    = $toBool($input['includeSymbols']    ?? null, false);
        $excludeAmbiguous  = $toBool($input['excludeAmbiguous']  ?? null, true);
        $requireEach       = $toBool($input['requireEach']       ?? null, true);

        // Al menos una categoría debe estar activa
        if (!$includeUppercase && !$includeLowercase && !$includeNumbers && !$includeSymbols) {
            throw new \InvalidArgumentException(
                'Al menos una categoría debe estar activa (includeUppercase, includeLowercase, includeNumbers, includeSymbols).'
            );
        }

        // Exclusión de caracteres
        $excludeChars = '';
        if (!empty($input['excludeChars']) && is_string($input['excludeChars'])) {
            $excludeChars = $input['excludeChars'];
        }

        return compact(
            'length',
            'includeUppercase',
            'includeLowercase',
            'includeNumbers',
            'includeSymbols',
            'excludeAmbiguous',
            'excludeChars',
            'requireEach'
        );
    }
}
