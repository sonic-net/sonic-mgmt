
multiple_acl_rules = {
	"acl": {
		"acl-sets": {
			"acl-set": {
				"L3_IPV4_INGRESS": {
					"acl-entries": {
						"acl-entry": {
							"1": {
								"actions": {
									"config": {
										"forwarding-action": "ACCEPT"
									}
								},
								"config": {
									"sequence-id": 1
								},
								"ip": {
									"config": {
										"source-ip-address": "192.138.10.1/32"

									}
								}
							},
							"2": {
								"actions": {
									"config": {
										"forwarding-action": "DROP"
									}
								},
								"config": {
									"sequence-id": 2
								},
								"ip": {
									"config": {
										"destination-ip-address": "12.12.12.12/16"

									}
								}
							}
						}
					}
				},
				"L3_IPV4_EGRESS": {
					"acl-entries": {
						"acl-entry": {
							"1": {
								"actions": {
									"config": {
										"forwarding-action": "ACCEPT"
									}
								},
								"config": {
									"sequence-id": 1
								},
								"ip": {
									"config": {
										"source-ip-address": "19.13.10.1/32"

									}
								}
							},
							"2": {
								"actions": {
									"config": {
										"forwarding-action": "DROP"
									}
								},
								"config": {
									"sequence-id": 2
								},
								"ip": {
									"config": {
										"destination-ip-address": "120.120.12.12/16"

									}
								}
							}
						}
					}
				},
				"L3_IPV6_INGRESS": {
					"acl-entries": {
						"acl-entry": {
							"1": {
								"actions": {
									"config": {
										"forwarding-action": "ACCEPT"
									}
								},
								"config": {
									"sequence-id": 1
								},
								"ip": {
									"config": {
										"source-ip-address": "2001::1/128"

									}
								}
							}
						}
					}
				},
				"L3_IPV6_EGRESS": {
					"acl-entries": {
						"acl-entry": {
							"1": {
								"actions": {
									"config": {
										"forwarding-action": "ACCEPT"
									}
								},
								"config": {
									"sequence-id": 1
								},
								"ip": {
									"config": {
										"source-ip-address": "6001::1/128"

									}
								}
							}
						}
					}
				}
			}
		}
	}
}
add_acl_rules = {
	"acl": {
		"acl-sets": {
			"acl-set": {
				"L3_IPV4_INGRESS": {
					"acl-entries": {
						"acl-entry": {
							"3": {
								"actions": {
									"config": {
										"forwarding-action": "DROP"
									}
								},
								"config": {
									"sequence-id": 3
								},
								"ip": {
									"config": {
										"source-ip-address": "185.185.1.1/16",
										"destination-ip-address": "181.182.1.1/16"

									}
								}
							}

						}
					}
				},
				"L3_IPV4_EGRESS": {
					"acl-entries": {
						"acl-entry": {
							"3": {
								"actions": {
									"config": {
										"forwarding-action": "DROP"
									}
								},
								"config": {
									"sequence-id": 3
								},
								"ip": {
									"config": {
										"source-ip-address": "10.185.10.1/16",
										"destination-ip-address": "11.12.10.1/16"

									}
								}
							}

						}
					}
				},
				"L3_IPV6_INGRESS": {
					"acl-entries": {
						"acl-entry": {
							"2": {
								"actions": {
									"config": {
										"forwarding-action": "ACCEPT"
									}
								},
								"config": {
									"sequence-id": 2
								},
								"ip": {
									"config": {
										"destination-ip-address": "3001::1/128"

									}
								}
							}
						}
					}
				},
				"L3_IPV6_EGRESS": {
					"acl-entries": {
						"acl-entry": {
							"2": {
								"actions": {
									"config": {
										"forwarding-action": "ACCEPT"
									}
								},
								"config": {
									"sequence-id": 2
								},
								"ip": {
									"config": {
										"destination-ip-address": "4001::1/128"

									}
								}
							}
						}
					}
				}
			}
		}
	}
}