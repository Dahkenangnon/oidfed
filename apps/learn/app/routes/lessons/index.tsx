import { redirect } from "react-router";

export function clientLoader() {
	return redirect("/lessons/what-is-federation");
}

export default function LessonsIndex() {
	return null;
}
