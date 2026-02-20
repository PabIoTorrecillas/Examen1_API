<?php

namespace App\Services;

/**
 * PasswordGenerator Service
 * Encapsula la lógica de generación segura de contraseñas.
 * Usa random_int() para entropía criptográfica (CSPRNG).
 */
class PasswordGenerator
{
    // Conjuntos de caracteres base
    private const UPPERCASE  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    private const LOWERCASE  = 'abcdefghijklmnopqrstuvwxyz';
    private const DIGITS     = '0123456789';
    private const SYMBOLS    = '!@#$%^&*()-_=+[]{}|;:,.<>?';
    private const AMBIGUOUS  = 'Il1O0o';

    // Límites de longitud permitidos
    public const MIN_LENGTH  = 4;
    public const MAX_LENGTH  = 128;
    public const MAX_COUNT   = 50;

    /**
     * Genera una sola contraseña segura.
     *
     * @param int    $length          Longitud deseada (4–128).
     * @param bool   $upper           Incluir mayúsculas.
     * @param bool   $lower           Incluir minúsculas.
     * @param bool   $digits          Incluir dígitos.
     * @param bool   $symbols         Incluir símbolos.
     * @param bool   $excludeAmbiguous Evitar caracteres ambiguos (Il1O0o).
     * @param string $exclude         Caracteres adicionales a excluir.
     * @param bool   $requireEach     Garantizar al menos 1 car. de cada categoría activa.
     *
     * @return string
     * @throws \InvalidArgumentException
     */
    public function generate(
        int    $length          = 16,
        bool   $upper           = true,
        bool   $lower           = true,
        bool   $digits          = true,
        bool   $symbols         = false,
        bool   $excludeAmbiguous = true,
        string $exclude         = '',
        bool   $requireEach     = true
    ): string {
        $this->validateLength($length);

        // Construir conjuntos activos
        $sets = [];
        if ($upper)   $sets['upper']   = self::UPPERCASE;
        if ($lower)   $sets['lower']   = self::LOWERCASE;
        if ($digits)  $sets['digits']  = self::DIGITS;
        if ($symbols) $sets['symbols'] = self::SYMBOLS;

        if (empty($sets)) {
            throw new \InvalidArgumentException(
                'Debe activarse al menos una categoría (upper/lower/digits/symbols).'
            );
        }

        // Construir mapa de exclusiones
        $excludeChars = $exclude;
        if ($excludeAmbiguous) {
            $excludeChars .= self::AMBIGUOUS;
        }
        $excludeMap = $this->buildExcludeMap($excludeChars);

        // Filtrar sets según exclusiones
        $sets = $this->filterSets($sets, $excludeMap);

        // Validar que require_each sea posible
        if ($requireEach && count($sets) > $length) {
            throw new \InvalidArgumentException(
                "La longitud ({$length}) es menor que el número de categorías activas (" . count($sets) . ")."
            );
        }

        // Pool total
        $pool = implode('', array_values($sets));

        $passwordChars = [];

        // Garantizar al menos un carácter por categoría
        if ($requireEach) {
            foreach ($sets as $chars) {
                $passwordChars[] = $chars[random_int(0, strlen($chars) - 1)];
            }
        }

        // Rellenar el resto
        $needed = $length - count($passwordChars);
        for ($i = 0; $i < $needed; $i++) {
            $passwordChars[] = $pool[random_int(0, strlen($pool) - 1)];
        }

        // Mezclar con Fisher-Yates seguro
        return $this->shuffleSecure(implode('', $passwordChars));
    }

    /**
     * Genera múltiples contraseñas con los mismos parámetros.
     *
     * @param int   $count  Número de contraseñas (1–50).
     * @param mixed ...$args Mismos parámetros que generate().
     *
     * @return string[]
     */
    public function generateMany(int $count, ...$args): array
    {
        if ($count < 1 || $count > self::MAX_COUNT) {
            throw new \InvalidArgumentException(
                'El parámetro count debe estar entre 1 y ' . self::MAX_COUNT . '.'
            );
        }

        $passwords = [];
        for ($i = 0; $i < $count; $i++) {
            $passwords[] = $this->generate(...$args);
        }
        return $passwords;
    }

    /**
     * Analiza la fortaleza de una contraseña dada.
     *
     * @param string $password     Contraseña a analizar.
     * @param array  $requirements Requisitos mínimos opcionales.
     *
     * @return array{score:int, strength:string, checks:array, passed:bool}
     */
    public function validate(string $password, array $requirements = []): array
    {
        $checks = [
            'hasUppercase'  => (bool) preg_match('/[A-Z]/', $password),
            'hasLowercase'  => (bool) preg_match('/[a-z]/', $password),
            'hasNumbers'    => (bool) preg_match('/[0-9]/', $password),
            'hasSymbols'    => (bool) preg_match('/[^A-Za-z0-9]/', $password),
            'length'        => strlen($password),
            'minLength'     => strlen($password) >= ($requirements['minLength'] ?? 8),
        ];

        // Requerimientos explícitos
        $requirementResults = [];
        $passed = true;

        if (isset($requirements['minLength'])) {
            $ok = $checks['length'] >= $requirements['minLength'];
            $requirementResults['minLength'] = $ok;
            if (!$ok) $passed = false;
        }
        foreach (['requireUppercase' => 'hasUppercase', 'requireLowercase' => 'hasLowercase',
                  'requireNumbers' => 'hasNumbers', 'requireSymbols' => 'hasSymbols'] as $req => $check) {
            if (!empty($requirements[$req])) {
                $ok = $checks[$check];
                $requirementResults[$req] = $ok;
                if (!$ok) $passed = false;
            }
        }

        // Puntaje 0–100
        $score = $this->computeScore($password, $checks);
        $strength = match(true) {
            $score >= 80 => 'strong',
            $score >= 60 => 'moderate',
            $score >= 40 => 'weak',
            default      => 'very_weak',
        };

        return [
            'score'              => $score,
            'strength'           => $strength,
            'checks'             => $checks,
            'requirementResults' => $requirementResults,
            'passed'             => $passed,
        ];
    }

    // ──────────────────────────────────────────────────────────────
    // Métodos privados
    // ──────────────────────────────────────────────────────────────

    private function validateLength(int $length): void
    {
        if ($length < self::MIN_LENGTH || $length > self::MAX_LENGTH) {
            throw new \InvalidArgumentException(
                sprintf(
                    'La longitud debe estar entre %d y %d caracteres.',
                    self::MIN_LENGTH,
                    self::MAX_LENGTH
                )
            );
        }
    }

    private function buildExcludeMap(string $chars): array
    {
        $arr = array_unique(preg_split('//u', $chars, -1, PREG_SPLIT_NO_EMPTY));
        return array_flip($arr);
    }

    private function filterSets(array $sets, array $excludeMap): array
    {
        foreach ($sets as $key => $chars) {
            $filtered = array_filter(
                preg_split('//u', $chars, -1, PREG_SPLIT_NO_EMPTY),
                fn($c) => !isset($excludeMap[$c])
            );
            if (empty($filtered)) {
                throw new \InvalidArgumentException(
                    "Después de aplicar exclusiones, la categoría '{$key}' quedó sin caracteres disponibles."
                );
            }
            $sets[$key] = implode('', array_values($filtered));
        }
        return $sets;
    }

    /**
     * Fisher-Yates shuffle usando random_int (criptográficamente seguro).
     */
    private function shuffleSecure(string $str): string
    {
        $arr = preg_split('//u', $str, -1, PREG_SPLIT_NO_EMPTY);
        $n = count($arr);
        for ($i = $n - 1; $i > 0; $i--) {
            $j = random_int(0, $i);
            [$arr[$i], $arr[$j]] = [$arr[$j], $arr[$i]];
        }
        return implode('', $arr);
    }

    private function computeScore(string $password, array $checks): int
    {
        $score = 0;
        $len = $checks['length'];

        // Longitud
        $score += match(true) {
            $len >= 20 => 30,
            $len >= 16 => 25,
            $len >= 12 => 20,
            $len >= 8  => 10,
            default    => 5,
        };

        // Variedad de caracteres
        if ($checks['hasUppercase']) $score += 15;
        if ($checks['hasLowercase']) $score += 15;
        if ($checks['hasNumbers'])   $score += 15;
        if ($checks['hasSymbols'])   $score += 20;

        // Bonus por alta entropía estimada
        $uniqueRatio = count(array_unique(str_split($password))) / max($len, 1);
        $score += (int)($uniqueRatio * 5);

        return min(100, $score);
    }
}
