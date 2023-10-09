package com.example.demo.controllers;

import com.example.demo.TestUtils;
import com.example.demo.model.persistence.Cart;
import com.example.demo.model.persistence.Item;
import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.repositories.CartRepository;
import com.example.demo.model.persistence.repositories.ItemRepository;
import com.example.demo.model.persistence.repositories.UserRepository;
import com.example.demo.model.requests.ModifyCartRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;
import org.springframework.http.ResponseEntity;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CartControllerTest {
    public static final String USERNAME = "test";
    private CartController cartController;
    private final CartRepository cartRepo = mock(CartRepository.class);
    private final UserRepository userRepo = mock(UserRepository.class);
    private final ItemRepository itemRepository = mock(ItemRepository.class);
    @Before
    public void setUp() {
        cartController = new CartController();
        TestUtils.injectObjects(cartController, "cartRepository", cartRepo);
        TestUtils.injectObjects(cartController, "userRepository", userRepo);
        TestUtils.injectObjects(cartController, "itemRepository", itemRepository);
    }
    @Test
    public void addToCart() {
        User user = new User();
        user.setUsername(USERNAME);
        Item item = com.example.demo.controllers.TestUtils.getItem0();
        Cart cart = new Cart();
        cart.setId(0L);
        List<Item> itemList = new ArrayList<>();
        itemList.add(item);
        cart.setUser(user);
        cart.setTotal(new BigDecimal("2.00"));
        cart.setItems(itemList);
        user.setCart(cart);
        when(userRepo.findByUsername(USERNAME)).thenReturn(user);
        when(itemRepository.findById(0L)).thenReturn(java.util.Optional.of(item));
        ModifyCartRequest request = new ModifyCartRequest();
        request.setItemId(0L);
        request.setUsername(USERNAME);
        request.setQuantity(1);
        ResponseEntity<Cart> response = cartController.addTocart(request);
        Assertions.assertNotNull(response);
        Assertions.assertEquals(200, response.getStatusCodeValue());
        Cart retrievedCart = response.getBody();
        Assertions.assertNotNull(retrievedCart);
        Assertions.assertEquals(0L, retrievedCart.getId());
        List<Item> items = retrievedCart.getItems();
        Assertions.assertNotNull(items);
        Item retrievedItem = items.get(0);
        Assertions.assertEquals(2, items.size());
        Assertions.assertNotNull(retrievedItem);
        Assertions.assertEquals(item, retrievedItem);
        Assertions.assertEquals(user, retrievedCart.getUser());
        Assertions.assertEquals(new BigDecimal("4.00"), retrievedCart.getTotal());
    }
    @Test
    public void removeCart() {
        User user = new User();
        user.setUsername(USERNAME);
        Item item = com.example.demo.controllers.TestUtils.getItem0();
        Cart cart = new Cart();
        cart.setId(0L);
        List<Item> itemList = new ArrayList<>();
        itemList.add(item);
        cart.setUser(user);
        cart.setTotal(new BigDecimal("2.00"));
        cart.setItems(itemList);
        user.setCart(cart);
        when(userRepo.findByUsername(USERNAME)).thenReturn(user);
        when(itemRepository.findById(0L)).thenReturn(java.util.Optional.of(item));
        ModifyCartRequest request = new ModifyCartRequest();
        request.setUsername(USERNAME);
        request.setItemId(0L);
        request.setQuantity(1);
        ResponseEntity<Cart> response = cartController.removeFromcart(request);
        assertNotNull(response);
        Assertions.assertEquals(200, response.getStatusCodeValue());
        Cart retrievedCart = response.getBody();
        assertNotNull(retrievedCart);
        Assertions.assertEquals(0L, retrievedCart.getId());
        List<Item> items = retrievedCart.getItems();
        assertNotNull(items);
        Assertions.assertEquals(0, items.size());
        Assertions.assertEquals(new BigDecimal("0.00"), retrievedCart.getTotal());
        Assertions.assertEquals(user, retrievedCart.getUser());
    }
    @Test
    public void testAddToCartNullUser() {
        User user = new User();
        user.setUsername(USERNAME);
        Item item = com.example.demo.controllers.TestUtils.getItem0();
        Cart cart = new Cart();
        cart.setId(0L);
        List<Item> itemList = new ArrayList<>();
        itemList.add(item);
        cart.setItems(itemList);
        cart.setTotal(new BigDecimal("2.00"));
        cart.setUser(user);
        user.setCart(cart);
        when(userRepo.findByUsername(USERNAME)).thenReturn(null);
        when(itemRepository.findById(0L)).thenReturn(java.util.Optional.of(item));
        ModifyCartRequest request = new ModifyCartRequest();
        request.setItemId(0L);
        request.setQuantity(1);
        request.setUsername(USERNAME);
        ResponseEntity<Cart> response = cartController.addTocart(request);
        assertNotNull(response);
        Assertions.assertEquals(404, response.getStatusCodeValue());
    }

}
