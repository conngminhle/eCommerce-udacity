package com.example.demo.controllers;

import com.example.demo.TestUtils;
import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.repositories.CartRepository;
import com.example.demo.model.persistence.repositories.UserRepository;
import com.example.demo.model.requests.CreateUserRequest;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static com.example.demo.controllers.CartControllerTest.USERNAME;
import static junit.framework.Assert.assertNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class UserControllerTest {
    public static final String PASSWORD = "Password";
    public static final String HASHED = "Hashed";
    private UserController userController;

    private final UserRepository userRepo = mock(UserRepository.class);

    private final CartRepository cartRepo = mock(CartRepository.class);

    private final BCryptPasswordEncoder encoder = mock(BCryptPasswordEncoder.class);

    @Before
    public void setUp() {
        userController = new UserController();
        com.example.demo.TestUtils.injectObjects(userController, "userRepository", userRepo);
        com.example.demo.TestUtils.injectObjects(userController, "cartRepository", cartRepo);
        TestUtils.injectObjects(userController, "bCryptPasswordEncoder", encoder);
    }
    @Test
    public void createUser() {
        when(encoder.encode(PASSWORD)).thenReturn(HASHED);
        CreateUserRequest r = new CreateUserRequest();
        r.setUsername(USERNAME);
        r.setPassword(PASSWORD);
        r.setConfirmPassword(PASSWORD);
        final ResponseEntity<User> response = userController.createUser(r);
        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        User u = response.getBody();
        assertNotNull(u);
        assertEquals(0, u.getId());
        assertEquals(USERNAME, u.getUsername());
        assertEquals(HASHED, u.getPassword());
    }
    @Test
    public void findByUserName() {
        when(encoder.encode(PASSWORD)).thenReturn(HASHED);
        CreateUserRequest r = new CreateUserRequest();
        r.setUsername(USERNAME);
        r.setPassword(PASSWORD);
        r.setConfirmPassword(PASSWORD);
        final ResponseEntity<User> response = userController.createUser(r);
        User user = response.getBody();
        when(userRepo.findByUsername(USERNAME)).thenReturn(user);
        final ResponseEntity<User> userResponseEntity = userController.findByUserName(USERNAME);
        User u = userResponseEntity.getBody();
        assertNotNull(u);
        assertEquals(0, u.getId());
        assertEquals(USERNAME, u.getUsername());
        assertEquals(HASHED, u.getPassword());
    }
    @Test
    public void findByUserNameNotExist() {
        when(encoder.encode(PASSWORD)).thenReturn(HASHED);
        CreateUserRequest r = new CreateUserRequest();
        r.setUsername(USERNAME);
        r.setPassword(PASSWORD);
        r.setConfirmPassword(PASSWORD);
        final ResponseEntity<User> response = userController.createUser(r);
        User user = response.getBody();
        when(userRepo.findByUsername(USERNAME)).thenReturn(user);
        final ResponseEntity<User> userResponseEntity = userController.findByUserName("MinhDuc");
        User u = userResponseEntity.getBody();
        assertNull(u);
        Assert.assertEquals(404, userResponseEntity.getStatusCodeValue());
    }
    @Test
    public void findById() {
        when(encoder.encode(PASSWORD)).thenReturn(HASHED);
        CreateUserRequest r = new CreateUserRequest();
        r.setUsername(USERNAME);
        r.setPassword(PASSWORD);
        r.setConfirmPassword(PASSWORD);
        final ResponseEntity<User> response = userController.createUser(r);
        User user = response.getBody();
        when(userRepo.findById(0L)).thenReturn(java.util.Optional.ofNullable(user));
        final ResponseEntity<User> userResponseEntity = userController.findById(0L);
        User u = userResponseEntity.getBody();
        assertNotNull(u);
        assertEquals(0, u.getId());
        assertEquals(USERNAME, u.getUsername());
        assertEquals(HASHED, u.getPassword());
    }
    @Test
    public void findByIdNotExist(){
        when(encoder.encode(PASSWORD)).thenReturn(HASHED);
        CreateUserRequest r = new CreateUserRequest();
        r.setUsername(USERNAME);
        r.setPassword(PASSWORD);
        r.setConfirmPassword(PASSWORD);
        final ResponseEntity<User> response = userController.createUser(r);
        User user = response.getBody();
        when(userRepo.findById(0L)).thenReturn(java.util.Optional.ofNullable(user));
        final ResponseEntity<User> userResponseEntity = userController.findById(1L);
        User u = userResponseEntity.getBody();
        assertNull(u);
        Assert.assertNotNull(userResponseEntity);
        Assert.assertEquals(404, userResponseEntity.getStatusCodeValue());
    }

}
