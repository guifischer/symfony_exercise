<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class IndexController extends AbstractController
{
    /**
     * @Route("/", name="index")
     */
    public function index(): Response
    {
        $cookie = new Cookie('access_token', $this->getUser()->getAccessToken()->getToken());

        $response = $this->render('index/index.html.twig');

        $response->headers->setCookie($cookie);

        return $response;
    }
}
