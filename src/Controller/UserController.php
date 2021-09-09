<?php

namespace App\Controller;

use App\Entity\User;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class UserController extends AbstractController
{
    /**
     * @Route("/api/users", name="users")
     */
    public function users(): Response
    {
        $users = $this->getDoctrine()
            ->getRepository(User::class)
            ->createQueryBuilder('users')
            ->getQuery()
            ->getArrayResult();

        $response = $this->json($users);

        $cookie = new Cookie('access_token', $this->getUser()->getAccessToken()->getToken());
        $response->headers->setCookie($cookie);

        return $response;
    }
}
