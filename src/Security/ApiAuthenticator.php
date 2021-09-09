<?php

namespace App\Security;

use App\Entity\AccessToken;
use DateTime;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class ApiAuthenticator extends AbstractAuthenticator
{
    private $entityManager;

    public function __construct(EntityManagerInterface $entityManager)
    {
        $this->entityManager = $entityManager;
    }

    public function supports(Request $request): ?bool
    {
        return $request->headers->has('Cookie');
    }

    public function authenticate(Request $request): PassportInterface
    {
        $headerCookies = explode('; ', $request->headers->get('Cookie'));
        $token = null;

        foreach ($headerCookies as $cookie) {
            list($key, $value) = explode('=', $cookie, 2);
            if ($key == "access_token") {
                $token = $value;
                break;
            }
        }

        $accessToken = $this->entityManager->getRepository(AccessToken::class)->findOneBy(array('token' => $token));

        if (null === $accessToken) {
            throw new CustomUserMessageAuthenticationException('API token not found or with wrong credentials');
        }

        $email = $accessToken->getUser()->getEmail();

        return new SelfValidatingPassport(new UserBadge($email));
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        $this->checkForExpiredAccessToken($token->getUser());

        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $data = [
            'message' => strtr($exception->getMessageKey(), $exception->getMessageData())
        ];

        return new JsonResponse($data, Response::HTTP_UNAUTHORIZED);
    }

    protected function checkForExpiredAccessToken(\App\Entity\User $user)
    {
        if ($user->getAccessToken()->getExpiresAt() > new DateTime()) {
            return;
        }

        $this->entityManager->remove($user->getAccessToken());
        $this->entityManager->flush();

        $access_token = new AccessToken($user);
        $user->setAccessToken($access_token);

        $this->entityManager->persist($access_token);
        $this->entityManager->flush();
    }
}
