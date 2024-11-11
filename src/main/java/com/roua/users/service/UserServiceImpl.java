package com.roua.users.service;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Optional;
import java.util.Random;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.roua.users.entities.Role;
import com.roua.users.entities.User;
import com.roua.users.repos.RoleRepository;
import com.roua.users.repos.UserRepository;
import com.roua.users.service.exceptions.EmailAlreadyExistsException;
import com.roua.users.service.exceptions.ExpiredTokenException;
import com.roua.users.service.exceptions.InvalidTokenException;
import com.roua.users.service.register.RegistrationRequest;
import com.roua.users.service.register.VerificationToken;
import com.roua.users.service.register.VerificationTokenRepository;
import com.roua.users.util.EmailSender;
@Transactional
@Service
public class UserServiceImpl implements UserService {
	
	@Autowired
	UserRepository userRepository ;
	
	@Autowired
	RoleRepository roleRepository ;
	
	@Autowired
	BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@Autowired
	 VerificationTokenRepository verificationTokenRepo;
	

	@Autowired
	 EmailSender emailSender ;
	


	@Override
	public User saveUser(User user) {
		user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
		return userRepository.save(user);
	}

	@Override
	public User findUserByUsername(String username) {
	
		return userRepository.findByUsername(username);
	}

	@Override
	public Role addRole(Role role) {
		
		return roleRepository.save(role);
	}

	@Override
	public User addRoleToUser(String username, String rolename) {
		
	    User usr= userRepository.findByUsername(username);
	    Role role= roleRepository.findByRole(rolename);
	    
	    usr.getRoles().add(role);
	    
	   // userRepository.save(usr);
	    
	    return usr;
	}

	@Override
	public List<User> findAllUsers() {
		
		return userRepository.findAll();
	}

	@Override
	public User registerUser(RegistrationRequest request) {
		
		Optional<User> optionaluser = userRepository.findByEmail(request.getEmail());
		
		if(optionaluser.isPresent())
		       throw new EmailAlreadyExistsException("email déjà existant!");
		
		User newUser = new User();
		newUser.setUsername(request.getUsername());
		newUser.setEmail(request.getEmail());
		newUser.setPassword(bCryptPasswordEncoder.encode(request.getPassword()));
		newUser.setEnabled(false);
		
		userRepository.save(newUser);
		
		//ajouter à newUser le role par défaut USER
		
		Role r = roleRepository .findByRole("USER");
		List<Role> roles = new ArrayList<>();
		
		roles.add(r);
		newUser.setRoles(roles);
		
		//génére le code secret
		String code = this.generateCode();
		VerificationToken token = new VerificationToken(code, newUser);
		verificationTokenRepo.save(token);
		
		sendEmailUser(newUser,token.getToken());
		
		
		
		return userRepository.save(newUser);


	}

	public String generateCode() {
		Random random = new Random();
		Integer code = 100000 + random.nextInt(900000);
		return code.toString();
		}
	@Override
	public void sendEmailUser(User u, String code) {
		String emailBody ="Bonjour "+ "<h1>"+u.getUsername() +"</h1>" +
		" Votre code de validation est "+"<h1>"+code+"</h1>";
		emailSender.sendEmail(u.getEmail(), emailBody);
	}

	@Override
	public User validateToken(String code) {
		VerificationToken token = verificationTokenRepo.findByToken(code);
		if (token == null) {
			throw new InvalidTokenException("Invalid Token");
		}
		User user = token.getUser();
		Calendar calendar = Calendar.getInstance();
		if ((token.getExpirationTime().getTime() - calendar.getTime().getTime()) <= 0) {
			verificationTokenRepo.delete(token);
			throw new ExpiredTokenException("expired Token");
		}
		user.setEnabled(true);
		userRepository.save(user);
		return user;
	}
}
