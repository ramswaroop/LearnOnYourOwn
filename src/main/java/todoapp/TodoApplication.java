package todoapp;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import todoapp.models.User;
import todoapp.repositories.UserRepository;

@SpringBootApplication
public class TodoApplication  {
     
    public static void main(String[] args) {
        SpringApplication.run(TodoApplication.class, args);
           
    }
//    public void run(String... args) throws Exception {
//    	implements CommandLineRunner
//    	repo.save(new User("sean@sean.ie", "password", "seaniemc", "Sean Mc", 1));
//    	repo.save(new User("gary@gary.ie", "password", "gary", "Gary Mc", 2));
//    	
//    	System.out.println("Customers found with findAll():");
//		System.out.println("-------------------------------");
//    	for (User customer : repo.findAll()) {
//			System.out.println(customer);
//		}
//    }
}
