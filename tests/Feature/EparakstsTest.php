<?php 

namespace Dencel\Eparaksts\Feature;

use Dencel\Eparaksts\Eparaksts;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Eparaksts::class)]
final class EparakstsTest extends TestCase
{
    protected string $host;
    protected string $username;
    protected string $password;
    protected string $redirect;

    protected function setUp(): void
    {
        parent::setUp();
        $this->host = $_ENV['EPARAKSTS_HOST'];
        $this->username = $_ENV['EPARAKSTS_USERNAME'];
        $this->password = $_ENV['EPARAKSTS_PASSWORD'];
        $this->redirect = $_ENV['EPARAKSTS_REDIRECT'];
    }

    public function test_can_create_token(): void
    {
        $eparaksts = new Eparaksts($this->username, $this->password, $this->host);
    
        $this->assertTrue($eparaksts->isAuthenticated());
    }

    public function test_can_fail_authentication(): void
    {
        $eparaksts = new Eparaksts('boo', 'hoo', $this->host);
    
        $this->assertFalse($eparaksts->isAuthenticated());
    }

    public function test_can_authorize_identification(): void 
    {
        $eparaksts = new Eparaksts($this->username, $this->password, $this->host);

        $this->assertTrue($eparaksts->isAuthenticated());

        
        $state = hash('sha256', $this->username.time().rand(1,9999));

        $result = $eparaksts->authorize('urn:lvrtc:fpeil:aa', $this->redirect, $state);
        $this->assertNotNull($result);

        echo $result;
    }
}