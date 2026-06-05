<?php

namespace Dencel\Eparaksts\Exception;

class ApiException extends EparakststException
{
    public function __construct(string $method, string $path, int $statusCode, string $body = '')
    {
        parent::__construct(sprintf('%s %s failed with status %d: %s', $method, $path, $statusCode, $body));
    }
}
