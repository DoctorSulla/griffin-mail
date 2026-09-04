<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { api } from '$lib/api';
	import Feedback from '$lib/Feedback.svelte';

	let unsubscribeText = $state('');
	let unsubscribeSignature = $state('');
	let loading = $state(false);
	let error = $state('');
	let success = $state('');

	onMount(() => {
		unsubscribeText = page.url.searchParams.get('unsubscribe_text') ?? '';
		unsubscribeSignature = page.url.searchParams.get('unsubscribe_signature') ?? '';
		if (!unsubscribeText || !unsubscribeSignature) {
			error = 'This unsubscribe link is incomplete.';
		}
	});

	async function unsubscribe() {
		loading = true;
		error = '';
		const result = await api.unsubscribe(unsubscribeText, unsubscribeSignature);
		loading = false;
		if (result.ok) {
			success = 'You have been removed from all Griffin Mail mailing lists.';
		} else {
			error = result.message;
		}
	}
</script>

<div class="mx-auto max-w-lg py-16 text-center">
	<h1 class="text-3xl font-bold text-gray-900">Unsubscribe</h1>
	<p class="mt-3 text-gray-600">
		This removes your address from the recipient directory and every mailing list.
	</p>
	<div class="mt-6"><Feedback {error} {success} /></div>
	{#if !success && unsubscribeText && unsubscribeSignature}
		<button
			type="button"
			disabled={loading}
			onclick={unsubscribe}
			class="mt-6 rounded-md bg-red-600 px-5 py-2 font-medium text-white hover:bg-red-700 disabled:opacity-50"
			>{loading ? 'Unsubscribing…' : 'Confirm unsubscribe'}</button
		>
	{/if}
</div>
