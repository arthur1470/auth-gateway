package br.com.flexpag.gateway.model;

import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.UUID;

@Getter
@Setter
public class AuthUserModel {

	private UUID id;
	private String name;
	private String email;
	private String cpf;
	private List<RoleModel> roles;
	private List<PermissionModel> permissions;
}
