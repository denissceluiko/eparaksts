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
     * Share a session with other persons.
     *
     * @param string $sessionId Session ID.
     * @param array $people List of person arrays, each with 'personId' (XXXXXX-YYYYY format) and 'accessRights'.
     * @param string $note Optional note for the recipients.
     * @return array|null Response body, or null on failure.
     * @link https://developers.eparaksts.lv/docs/share-api
     */
    public function start(string $sessionId, array $people, string $note = ''): ?array
    {
        $response = $this->signAPI->post(static::ENDPOINT . $sessionId . '/persons', [
            'headers' => [
                'Content-Type' => 'application/json',
            ],
            'body' => json_encode([
                'persons' => $people,
                'note'    => $note,
            ]),
        ]);
        return json_decode($response->getBody()->getContents(), true);
    }

    /**
     * Remove a person's access to a shared session.
     *
     * @param string $sessionId Session ID.
     * @param string $personId Latvian personal number in XXXXXX-YYYYY format.
     * @return array|null Response body, or null on failure.
     */
    public function delete(string $sessionId, string $personId): ?array
    {
        $response = $this->signAPI->delete(static::ENDPOINT . $sessionId . '/persons/' . $personId);
        return json_decode($response->getBody()->getContents(), true);
    }

    /**
     * List persons who have access to a session.
     *
     * @param string $sessionId Session ID.
     * @return array|null List of persons, or null on failure.
     */
    public function persons(string $sessionId): ?array
    {
        $response = $this->signAPI->get(static::ENDPOINT . $sessionId . '/persons');
        return json_decode($response->getBody()->getContents(), true);
    }

    /**
     * List sessions shared with a person.
     *
     * Note: personId must be in XXXXXX-YYYYY format, not the PNOLV-XXXXXX-YYYYY format used elsewhere.
     *
     * @param string $personId Latvian personal number in XXXXXX-YYYYY format.
     * @return array|null List of sessions, or null on failure.
     */
    public function sessions(string $personId): ?array
    {
        $response = $this->signAPI->get(static::ENDPOINT . $personId . '/sessions');
        return json_decode($response->getBody()->getContents(), true);
    }
}
