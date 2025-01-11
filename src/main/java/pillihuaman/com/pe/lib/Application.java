package pillihuaman.com.pe.lib;

import org.springframework.boot.SpringApplication;
import org.springframework.context.annotation.ComponentScan;

@ComponentScan()
public class Application {

	
	public static void main(String[] args) {
		SpringApplication app = new SpringApplication(Application.class);
		//app.setDefaultProperties(Collections.singletonMap("server.port", "8091"));
		app.run(args);
	}


}

