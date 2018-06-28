<?php
/**
 * Implement basic LDAP Server for Testing Purposes
 */
use FreeDSx\Ldap\Server\RequestHandler\GenericRequestHandler;
use FreeDSx\Ldap\Server\RequestContext;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Entry\Entries;


class LdapRequestHandler extends GenericRequestHandler
{
    /**
     * @var array
     */
    protected $users = [
        'user' => '12345',
    ];

    /**
     * Validates the username/password of a simple bind request
     *
     * @param string $username
     * @param string $password
     * @return bool
     */
    public function bind(string $username, string $password): bool
    {
        return isset($this->users[$username]) && $this->users[$username] === $password;
    }

    /**
     * Override the search request. This must send back an entries object.
     *
     * @param RequestContext $context
     * @param SearchRequest $search
     * @return Entries
     */
    public function search(RequestContext $context, SearchRequest $search): Entries
    {
        return new Entries(
            Entry::create('cn=Foo,dc=FreeDSx,dc=local', [
                'cn' => 'Foo',
                'sn' => 'Bar',
                'givenName' => 'Foo',
            ]),
            Entry::create('cn=Chad,dc=FreeDSx,dc=local', [
                'cn' => 'Chad',
                'sn' => 'Sikorra',
                'givenName' => 'Chad',
            ])
        );
    }
}
