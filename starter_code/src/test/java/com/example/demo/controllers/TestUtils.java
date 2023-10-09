package com.example.demo.controllers;

import com.example.demo.model.persistence.Item;

import java.math.BigDecimal;

public class TestUtils {
    public static Item getItem0() {
        Item item = new Item();
        item.setId(0L);
        item.setName("Widget 0");
        item.setPrice(new BigDecimal("2.00"));
        item.setDescription("A widget 0");
        return item;
    }
    public static Item getItem1() {
        Item item = new Item();
        item.setId(1L);
        item.setName("Widget 1");
        item.setPrice(new BigDecimal("1.00"));
        item.setDescription("A widget 1");
        return item;
    }
}
