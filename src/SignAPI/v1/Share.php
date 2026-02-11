<?php 

namespace Dencel\Eparaksts\SignAPI\v1;

class Share
{
    protected SignAPI $signAPI;

    public const ENDPOINT = '/api-share/v1.0/';

    public function __construct(SignAPI $signAPI)
    {
        $this->signAPI = $signAPI;
    }
    
    /**
     * $people should be formatted like [["personId" => "111111-11111", "accessRights" => 5], [...], ...]
     *
     * For full $people formatting rules and assess rights format refer to the docs
     * @link https://developers.eparaksts.lv/docs/share-api 
     */
    public function start(string $sessionId, array $people, string $note = ''): ?array
    {
        $response = $this->signAPI->post(static::ENDPOINT . $sessionId . '/persons', [
            'body' => json_encode([
                'persons' => $people,
                'note' => $note,
            ])
        ]);
        return json_decode($response->getBody()->getContents(), true);
    }

    public function delete(string $sessionId, string $personId): ?array
    {
        $response = $this->signAPI->delete(static::ENDPOINT . $sessionId . '/persons/' . $personId);
        return json_decode($response->getBody()->getContents(), true);
    }

    public function persons(string $sessionId): ?array
    {
        $response = $this->signAPI->get(static::ENDPOINT . $sessionId . '/persons');
        return json_decode($response->getBody()->getContents(), true);
    }

    /**
     * Docs say person id shoul be fromatted like XXXXXX-YYYYY
     * Why not PNOLV-XXXXXX-YYYYY? Who knows, be careful.
     */
    public function sessions(string $personId): ?array
    {
        $response = $this->signAPI->get(static::ENDPOINT . $personId . '/sessions');
        return json_decode($response->getBody()->getContents(), true);
    }
}