package com.microproject.service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import com.microproject.models.ErrorMessages;
import com.microproject.models.PermissionResponse;
import com.microproject.models.ResourceActionResponse;


@Service
public class PermissionService {
	
	public static Object getPermissionsWithInheritance(List<String> lines) {
		Set<String> predefinedRoles = new HashSet<>();
		Set<String> predefinedResources = new HashSet<>();
		Set<String> predefinedActions = new HashSet<>();
		Map<String, List<String>> roleInheritanceMap = new HashMap<>();
		Map<String, Map<String, List<String>>> roleResourceActionsMap = new HashMap<>();
		for (String line : lines) {
			String[] parts = line.split("\\s+");
			String inputString = line;
			if (line.startsWith("role")) {
				String roleName = extractValue(inputString, "role\\s(\\S+)");
				predefinedRoles.add(roleName);
			} else if (line.startsWith("resource")) {
				String resourceName = extractValue(inputString, "resource\\s(\\S+)");
				predefinedResources.add(resourceName);
			} else if (line.startsWith("action")) {
				String actionName = extractValue(inputString, "action\\s(\\S+)");
				predefinedActions.add(actionName);
			} else if (line.startsWith("inrole") && parts[0].equals("inrole")) {
				String role = extractValue(inputString, "inrole role\\(([^,]+), ([^)]+)\\)");
				String inheritedRole = extractValue(inputString, "inrole role\\([^,]+, ([^)]+)\\)");
				roleInheritanceMap.computeIfAbsent(role, k -> new ArrayList<>()).add(inheritedRole);
			} else if (parts.length >= 4 && parts[0].equals("priv")) {
				processPrivLine(inputString, roleResourceActionsMap);
			}
		}
		List<ErrorMessages> errorPermissions = new ArrayList<>();
		ErrorMessages errorPermission = new ErrorMessages();
		List<PermissionResponse> permissions = new ArrayList<>();

		for (Map.Entry<String, Map<String, List<String>>> roleEntry : roleResourceActionsMap.entrySet()) {
			String currentRole = roleEntry.getKey();
			PermissionResponse permission = new PermissionResponse();
			permission.setRole(currentRole);

			// Check predefined roles
			boolean checkRole = checkRoleAndResource(predefinedRoles, currentRole);
			if (!checkRole) {
				errorPermission.setMessage("Role '" + currentRole + "' is not defined!!");
				errorPermissions.add(errorPermission);
				return errorPermissions;
			}

			// Set inherited roles
			List<String> inheritedRoles = roleInheritanceMap.get(currentRole);
			permission.setInheritedRoles(inheritedRoles != null ? inheritedRoles : Collections.emptyList());
			List<ResourceActionResponse> resourceActions = new ArrayList<>();
			for (Map.Entry<String, List<String>> resourceEntry : roleEntry.getValue().entrySet()) {
				ResourceActionResponse resourceAction = new ResourceActionResponse();
				resourceAction.setResource(resourceEntry.getKey());
				resourceAction.setActions(resourceEntry.getValue());
				resourceActions.add(resourceAction);

				// Check predefined resources
				String resource = resourceAction.getResource();
				boolean checkResource = checkRoleAndResource(predefinedResources, resource);
				if (!checkResource) {
					errorPermission.setMessage("Resource '" + resource + "' is not defined!!");
					errorPermissions.add(errorPermission);
					return errorPermissions;
				}

				// Check predefined actions
				List<String> actions = resourceAction.getActions();
				List<String> undefinedActions = checkActions(actions, predefinedActions);
				if (!undefinedActions.isEmpty()) {
					// Convert the list of undefined actions to a string representation
					String undefinedActionsAsString = String.join(", ", undefinedActions);
					errorPermission.setMessage("Action '" + undefinedActionsAsString + "' is not defined!!");
					errorPermissions.add(errorPermission);
					return errorPermissions;
				}
			}
			permission.setResourceActions(resourceActions);
			permissions.add(permission);
		}
		List<ErrorMessages> errorMessage = applyInheritance(permissions, predefinedRoles);
		if (errorMessage.isEmpty()) {
			return permissions;

		}
		return errorMessage;
	}

	public static List<ErrorMessages> applyInheritance(List<PermissionResponse> permissions,
			Set<String> predefinedRoles) {
		Map<String, List<String>> roleInheritanceMap = new HashMap<>();
		List<ErrorMessages> errors = new ArrayList<>();
		// Populate roleInheritanceMap based on inrole lines
		for (PermissionResponse permission : permissions) {
			List<String> inheritedRoles = permission.getInheritedRoles();
			if (inheritedRoles != null) {
				String role = permission.getRole();
				roleInheritanceMap.computeIfAbsent(role, k -> new ArrayList<>()).addAll(inheritedRoles);
			}
		}
		// Check if all inherited roles are available in the predefined set
		for (List<String> inheritedRoles : roleInheritanceMap.values()) {
			for (String inheritedRole : inheritedRoles) {
				if (!predefinedRoles.contains(inheritedRole)) {
					// Accumulate error messages for inherited roles not in the predefined set
					ErrorMessages error = new ErrorMessages();
					error.setMessage("Inherited role '" + inheritedRole + "' is not available!!");
					errors.add(error);
				}
			}
		}
		if (!errors.isEmpty()) {
			return errors; // Return errors if any inherited roles are not available
		}

		// Apply inheritance
		for (PermissionResponse permission : permissions) {
			List<String> inheritedRoles = roleInheritanceMap.get(permission.getRole());
			if (inheritedRoles != null) {
				for (String inheritedRole : inheritedRoles) {
					for (PermissionResponse inheritedPermission : permissions) {
						if (inheritedPermission.getRole().equals(inheritedRole)) {
							// Inherit resource actions
							List<ResourceActionResponse> mergedResourceActions = mergeResourceActions(
									permission.getResourceActions(), inheritedPermission.getResourceActions());
							permission.setResourceActions(mergedResourceActions);
						}
					}
				}
			}
		}
		return errors;
	}

	private static List<ResourceActionResponse> mergeResourceActions(List<ResourceActionResponse> resourceActions,
			List<ResourceActionResponse> inheritedResourceActions) {
		Map<String, Set<String>> resourceActionMap = new HashMap<>();

		// Add resource actions from the base permission
		for (ResourceActionResponse resourceAction : resourceActions) {
			resourceActionMap.computeIfAbsent(resourceAction.getResource(), k -> new HashSet<>())
					.addAll(resourceAction.getActions());
		}

		// Add resource actions from the inherited permission
		for (ResourceActionResponse inheritedResourceAction : inheritedResourceActions) {
			resourceActionMap.computeIfAbsent(inheritedResourceAction.getResource(), k -> new HashSet<>())
					.addAll(inheritedResourceAction.getActions());
		}

		// Convert the map to a list of ResourceAction objects
		List<ResourceActionResponse> mergedResourceActions = new ArrayList<>();
		for (Map.Entry<String, Set<String>> entry : resourceActionMap.entrySet()) {
			ResourceActionResponse mergedResourceAction = new ResourceActionResponse();
			mergedResourceAction.setResource(entry.getKey());
			mergedResourceAction.setActions(new ArrayList<>(entry.getValue()));
			mergedResourceActions.add(mergedResourceAction);
		}

		return mergedResourceActions;
	}

	private static boolean checkRoleAndResource(Set<String> roleSet, String element) {
		if (!roleSet.contains(element)) {
			return false; // Key not found in the set values
		}
		return true; // Every key is present in the set values
	}

	private static List<String> checkActions(List<String> actions, Set<String> predefinedActions) {
		List<String> undefinedActions = new ArrayList<>();

		for (String action : actions) {
			if (!predefinedActions.contains(action)) {
				undefinedActions.add(action);
			}
		}
		return undefinedActions;
	}

	private static void processPrivLine(String inputString,
			Map<String, Map<String, List<String>>> roleResourceActionsMap) {
		String modifiedInputString = inputString.replaceAll("\\s*,\\s*", ",");
		String pattern = "priv permission\\(\\s*([^,]+)\\s*,\\s*([^,]+)\\s*,\\s*([^)]+?)\\s*\\)";
		Matcher matcher = Pattern.compile(pattern).matcher(modifiedInputString);

		if (matcher.matches()) {
			String role = matcher.group(1);
			String resource = matcher.group(2);
			String action = matcher.group(3);

			roleResourceActionsMap.computeIfAbsent(role, k -> new HashMap<>())
					.computeIfAbsent(resource, k -> new ArrayList<>()).add(action);
		}
	}

	private static String extractValue(String inputString, String pattern) {
		Matcher matcher = Pattern.compile(pattern).matcher(inputString);
		return matcher.find() ? matcher.group(1) : "";
	}

	public static Object getPermissionsForRole(List<String> lines, List<String> rolesList) {
		Set<String> predefinedRoles = new HashSet<>();
		Set<String> predefinedResources = new HashSet<>();
		Set<String> predefinedActions = new HashSet<>();
		Map<String, List<String>> roleInheritanceMap = new HashMap<>();
		Map<String, Map<String, List<String>>> roleResourceActionsMap = new HashMap<>();
		List<String> lowercaseRolesList = rolesList.stream().map(String::toLowerCase).collect(Collectors.toList());
		for (String line : lines) {
			String[] parts = line.split("\\s+");
			String inputString = line;
			if (line.startsWith("role")) {
				String roleName = extractValue(inputString, "role\\s(\\S+)");
				predefinedRoles.add(roleName);
			} else if (line.startsWith("resource")) {
				String resourceName = extractValue(inputString, "resource\\s(\\S+)");
				predefinedResources.add(resourceName);
			} else if (line.startsWith("action")) {
				String actionName = extractValue(inputString, "action\\s(\\S+)");
				predefinedActions.add(actionName);
			} else if (line.startsWith("inrole") && parts[0].equals("inrole")) {
				String role = extractValue(inputString, "inrole role\\(([^,]+), ([^)]+)\\)");
				String inheritedRole = extractValue(inputString, "inrole role\\([^,]+, ([^)]+)\\)");
				roleInheritanceMap.computeIfAbsent(role, k -> new ArrayList<>()).add(inheritedRole);
			} else if (parts.length >= 4 && parts[0].equals("priv")) {
				processPrivLine(inputString, roleResourceActionsMap);
			}
		}

		List<ErrorMessages> errorPermissions = new ArrayList<>();
		ErrorMessages errorPermission = new ErrorMessages();
		List<PermissionResponse> permissions = new ArrayList<>();
		List<PermissionResponse> inheritPermissions = new ArrayList<PermissionResponse>();

		for (String requestedRole : rolesList) {
			// Check if the requested role is available in the predefined roles
			// (case-insensitive)
			if (requestedRole == null || requestedRole.trim().isEmpty()) {
				continue;
			}
			if (!predefinedRoles.stream().anyMatch(role -> role.equalsIgnoreCase(requestedRole))) {
				errorPermission.setMessage("Role '" + requestedRole + "' is not available.");
				errorPermissions.add(errorPermission);
			}
		}

		if (!errorPermissions.isEmpty()) {
			return errorPermissions;
		}

		for (Map.Entry<String, Map<String, List<String>>> roleEntry : roleResourceActionsMap.entrySet()) {
			String currentRole = roleEntry.getKey();

			// Check if the current role is in the requested roles list
			PermissionResponse permission = new PermissionResponse();
			permission.setRole(currentRole);

			// Check predefined roles
			boolean checkRole = checkRoleAndResource(predefinedRoles, currentRole);
			if (!checkRole) {
				errorPermission.setMessage("Role '" + currentRole + "' is not defined!!");
				errorPermissions.add(errorPermission);
				return errorPermissions;
			}

			// Set inherited roles
			List<String> inheritedRoles = roleInheritanceMap.get(currentRole);
			permission.setInheritedRoles(inheritedRoles != null ? inheritedRoles : Collections.emptyList());
			List<ResourceActionResponse> resourceActions = new ArrayList<>();
			for (Map.Entry<String, List<String>> resourceEntry : roleEntry.getValue().entrySet()) {
				ResourceActionResponse resourceAction = new ResourceActionResponse();
				resourceAction.setResource(resourceEntry.getKey());
				resourceAction.setActions(resourceEntry.getValue());
				resourceActions.add(resourceAction);

				// Check predefined resources
				String resource = resourceAction.getResource();
				boolean checkResource = checkRoleAndResource(predefinedResources, resource);
				if (!checkResource) {
					errorPermission.setMessage("Resource '" + resource + "' is not defined!!");
					errorPermissions.add(errorPermission);
					return errorPermissions;
				}
				List<String> actions = resourceAction.getActions();
				List<String> undefinedActions = checkActions(actions, predefinedActions);
				if (!undefinedActions.isEmpty()) {
					// Convert the list of undefined actions to a string representation
					String undefinedActionsAsString = String.join(", ", undefinedActions);
					errorPermission.setMessage("Action '" + undefinedActionsAsString + "' is not defined!!");
					errorPermissions.add(errorPermission);
					return errorPermissions;
				}
			}
			permission.setResourceActions(resourceActions);
			if (lowercaseRolesList.contains(currentRole.toLowerCase())) {
				permissions.add(permission);
			}
			inheritPermissions.add(permission);
		}
		List<ErrorMessages> errorMessage = applyInheritance(inheritPermissions, predefinedRoles);
		if (errorMessage.isEmpty()) {
			return permissions;

		}
		return errorMessage;
	}
}