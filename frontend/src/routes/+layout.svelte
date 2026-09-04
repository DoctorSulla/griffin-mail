<script lang="ts">
	import '../app.css';
	import favicon from '$lib/assets/favicon.svg';
	import { page } from '$app/state';
	import { afterNavigate } from '$app/navigation';
	import { api } from '$lib/api';
	import { goto } from '$app/navigation';

	let { children } = $props();

	interface Route {
		text: string;
		href: string;
		allowed: 'always' | 'authenticated' | 'unauthenticated';
		navigation?: boolean;
	}

	let links: Route[] = $state([]);

	const routes: Route[] = [
		{ text: 'Home', href: '/', allowed: 'always' },
		{ text: 'Register', href: '/register', allowed: 'unauthenticated' },
		{ text: 'Login', href: '/login', allowed: 'unauthenticated' },
		{
			text: 'Reset password',
			href: '/resetPassword',
			allowed: 'unauthenticated',
			navigation: false
		},
		{ text: 'Unsubscribe', href: '/unsubscribe', allowed: 'always', navigation: false },
		{ text: 'Lists', href: '/lists', allowed: 'authenticated' },
		{ text: 'List details', href: '/lists/detail', allowed: 'authenticated', navigation: false },
		{ text: 'Recipients', href: '/addRecipients', allowed: 'authenticated' },
		{ text: 'Create list', href: '/createList', allowed: 'authenticated', navigation: false },
		{ text: 'Permissions', href: '/permissions', allowed: 'authenticated' },
		{ text: 'Profile', href: '/profile', allowed: 'authenticated' }
	];

	function currentRoute(): Route | null {
		return routes.find((route) => route.href === page.route.id) ?? null;
	}

	let title = $derived.by(() => {
		if (currentRoute()) {
			return currentRoute()?.text;
		}
		return 'Griffin Mail';
	});

	let loggedIn = $state(false);

	afterNavigate(async function () {
		let route = currentRoute();
		let response = await api.getProfile();
		if (response.response_type == 'Error') {
			loggedIn = false;
			links = routes.filter(
				(route) => route.navigation !== false && route.allowed !== 'authenticated'
			);
			if (route?.allowed == 'authenticated') {
				goto('/login');
			}
		} else {
			loggedIn = true;
			links = routes.filter(
				(route) => route.navigation !== false && route.allowed !== 'unauthenticated'
			);
			if (route?.allowed == 'unauthenticated') {
				goto('/profile');
			}
		}
	});

	async function logout() {
		await api.logout();
		goto('/login');
	}
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<title>{title}</title>
</svelte:head>

<nav class="bg-blue-700 px-3 py-3">
	<div class="m-auto flex max-w-7xl flex-wrap items-center gap-x-5 gap-y-2">
		{#each links as link}
			<a class="font-medium text-white hover:text-blue-100" href={link.href}>{link.text}</a>
		{/each}
		{#if loggedIn}
			<button class="cursor-pointer font-medium text-white hover:text-blue-100" onclick={logout}>
				Logout
			</button>
		{/if}
	</div>
</nav>
<main class="m-auto max-w-7xl px-4">
	{@render children?.()}
</main>
