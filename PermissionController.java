package com.microproject.controller;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.microproject.service.PermissionService;

@RestController
public class PermissionController {
	
	@Autowired
	private PermissionService permissionService;
	
	@PostMapping("/roleInheritance")
	public ResponseEntity<Object> getPermissionsWithInheritance(@RequestParam(required = false) List<String> rolesList) {
	    try {
	        Path filePath = Paths.get("src/main/resources/data.ftl");
	        List<String> lines = Files.readAllLines(filePath);
	        Object permissions;

	        if (rolesList != null && !rolesList.isEmpty()) {
	            permissions = permissionService.getPermissionsForRole(lines, rolesList);
	        } else {
	            permissions = permissionService.getPermissionsWithInheritance(lines);
	        }

	        return ResponseEntity.ok(permissions);
	    } catch (IOException e) {
	        e.printStackTrace();
	        return ResponseEntity.status(500).body(null);
	    }
	}
	
}
