package com.microproject.models;

import java.util.Collections;
import java.util.List;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PermissionResponse {
	private String role;
	private List<ResourceActionResponse> resourceActions;
	private List<String> inheritedRoles;
	
	@JsonProperty("role")
	public String getRole() {
		return role;
	}

	@JsonProperty("resourceActions")
	public List<ResourceActionResponse> getResourceActions() {
		return resourceActions;
	}

	@JsonProperty("inheritedRoles")
	public List<String> getInheritedRoles() {
		return inheritedRoles != null ? inheritedRoles : Collections.emptyList();
	}

	public void setInheritedRoles(List<String> inheritedRoles) {
		this.inheritedRoles = inheritedRoles;
	}
}
