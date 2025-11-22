package com.example.microservices.product.domain.enums;

/**
 * Product categories
 */
public enum Category {
    ELECTRONICS("Electronics"),
    CLOTHING("Clothing"),
    FOOD("Food & Beverages"),
    BOOKS("Books"),
    HOME("Home & Garden"),
    SPORTS("Sports & Outdoors"),
    TOYS("Toys & Games"),
    BEAUTY("Beauty & Personal Care"),
    AUTOMOTIVE("Automotive"),
    OTHER("Other");

    private final String displayName;

    Category(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
