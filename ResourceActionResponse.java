package com.microproject.models;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ResourceActionResponse {
	
	private String resource;
	
	private List<String> actions;

	@JsonProperty("resource")
	public String getResource() {
		return resource;
	}

	@JsonProperty("actions")
	public List<String> getActions() {
		return actions;
	}

}
