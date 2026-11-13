package com.krakedev.jwt.service;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

@Service
public class TokenBlackListService {
	
	private final Set<String> blacklist = ConcurrentHashMap.newKeySet();
	
	public void invalidarToken(String token) {
		blacklist.add(token);
	}
	
	public boolean estaInvalidado(String token) {
		return blacklist.contains(token);
	}

}
