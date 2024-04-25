<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManager;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;

#[Route('/api')]
class SecurityController extends AbstractController
{

    private UserPasswordHasherInterface $passwordHasher;
    private EntityManagerInterface $em;
    private UserRepository $userRepo;
    private JWTTokenManagerInterface $JWTManager;

    public function __construct(UserPasswordHasherInterface $passwordHasher, EntityManagerInterface $em, UserRepository $userRepo, JWTTokenManagerInterface $JWTManager){
        $this->passwordHasher = $passwordHasher;
        $this->em = $em;
        $this->userRepo = $userRepo;
        $this->JWTManager = $JWTManager;
    }


    #[Route('/register', name: 'app_register', methods:['POST'])]
    public function register(Request $request): JsonResponse
    {
        // Récupérer les données envoyés par l'utilisateur depuis vueJS  
        $data = json_decode($request->getContent(), true);

        // Créer un nouvel utilisateur 
        $user = new User();
        $user->setEmail($data['email']);
        $user->setPassword(
            $this->passwordHasher->hashPassword(
                $user, 
                $data['password']
                )
            );
        $user->setRoles(['ROLE_USER']);

        $this->em->persist($user);
        $this->em->flush();
            
        return $this->json([
            'id'=>$user->getId(),
            'email'=>$user->getEmail(),
            'password'=>$user->getPassword(),
            'role'=>$user->getRoles(),
        ], JsonResponse::HTTP_CREATED);
    }


    #[Route('/login', name: 'app_login', methods:['POST'])]
    public function login(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true);

        // Vérifier si l'utilisateur existe en BDD 
        $user = $this->userRepo->findOneBy(['email'=> $data['email']]);

        // Comparaison des infos utilisateurs avec les infos de la BDD 
        if (!$user || !$this->passwordHasher->isPasswordValid($user, $data['password'])){
            return new JsonResponse(['error'=>'Email ou mot de passe incorrect'], JsonResponse::HTTP_UNAUTHORIZED);
        }

        // Créer un JWT pour authentifier le user 
        $token = $this->JWTManager->create($user);

        $res = new JsonResponse([
            'message'=>'Connection réussie'
        ]);

        // Envoyer le JWT dans un Cookie -> C'est plus sécure que de le stocker dans le localStorage car non accéssible via le JS -> se protéger conter les failles XSS(injection de js)
        $res->headers->setCookie(new Cookie('BEARER', $token, time() + 3600, '/', null, true, true));
        return $res;
    }

    #[Route('/logout', name: 'app_logout', methods:['POST'])]
    public function logout(): JsonResponse
    {
        $res = new JsonResponse([
            'message'=>'Déconnection réussie'
        ]);
        // Supprimer le JWT à la deconnection
        $res->headers->clearCookie('BEARER');
        return $res;

    }
}
