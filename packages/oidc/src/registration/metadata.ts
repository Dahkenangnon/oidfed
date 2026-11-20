/** Extracts `client_registration_types_supported` from OP metadata. */
export function getRegistrationTypes(opMeta: Record<string, unknown> | undefined): string[] {
	return (opMeta?.client_registration_types_supported as string[] | undefined) ?? [];
}
