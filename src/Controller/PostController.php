<?php

namespace App\Controller;

use App\Entity\Posts;
use App\Repository\PostsRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Serializer\SerializerInterface;
#[Route('/api')]
class PostController extends AbstractController
{
    private $postRepo;
    private $em;

    public function __construct(PostsRepository $postRepo, EntityManagerInterface $em)
    {
        $this->postRepo = $postRepo;
        $this->em = $em;
    }
    // Renvoyer tous les posts en JSON
    #[Route('/posts', name: 'get_all_posts', methods: ['GET'])]
    public function getAllPosts(SerializerInterface $serializer): JsonResponse
    {
        $posts = $this->postRepo->findAll();
        // Faire des groupes de serialization avec l'annotation #Groups dans l'entité Posts
        // $jsonGroups = $serializer->serialize($posts, 'json', ['groups' => 'groupe2']);
 
        return $this->json($posts);
    }

    // Renvoyer un post spécifique en JSON
    #[Route('/posts/{id}', name: 'get_post', methods: ['GET'])]
    public function getPost($id): JsonResponse
    {
        $post = $this->postRepo->find($id);

        if(!$post) {
            return $this->json(['message' => 'Post n\'existe pas'], Response::HTTP_NOT_FOUND);
        }

        return $this->json($post);
    }


        // Créer un post 
        #[Route('/posts', name: 'create_post', methods: ['POST'])]
        public function createPost(Request $request): JsonResponse
        {
            // Récupérer les données envoyées par le front sous forme de tableau associatif (true)
            $data = json_decode($request->getContent(), true);

            // Créer une nouvelle instance de Posts avec les données envoyés par le front  
            $post = new Posts();
            $post->setTitle($data['title']);
            $post->setContent($data['content']);

            $this->em->persist($post);
            $this->em->flush();
    
            return $this->json($post);
        }


        // Modifier un post 
        #[Route('/posts/{id}', name: 'update_post', methods: ['PUT'])]
        public function updatePost($id,Request $request): JsonResponse
        {
            // Récupérer les données envoyées par le front sous forme de tableau associatif (true)
            $data = json_decode($request->getContent(), true);

            // Récupérer le post à modifier
            $post = $this->postRepo->find($id);
            // Vérifier si le post existe
            if(!$post) {
                return $this->json(['message' => 'Post n\'existe pas'], Response::HTTP_NOT_FOUND);
            } 

            // Modifier les props du posts qui ont été changés par les données envoyées par le front 
            $post->setTitle($data['title'] ?? $post->getTitle());
            $post->setContent($data['content'] ?? $post->getContent());

            $this->em->persist($post);
            $this->em->flush();
    
            return $this->json($post);
        }

        // Supprimer un post spécifique
        #[Route('/posts/{id}', name: 'delete_post', methods: ['DELETE'])]
        public function deletePost($id): JsonResponse
        {
            $post = $this->postRepo->find($id);

            if(!$post) {
                return $this->json(['message' => 'Post n\'existe pas'], Response::HTTP_NOT_FOUND);
            }
            $this->em->remove($post);
            $this->em->flush();

            return new JsonResponse(['message' => 'Post supprimé'], Response::HTTP_OK);
        }
}
