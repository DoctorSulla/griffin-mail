<script lang="ts">
	import { goto } from '$app/navigation';
	import { api } from '$lib/api';
	import Feedback from '$lib/Feedback.svelte';

	let name = $state('');
	let description = $state('');
	let loading = $state(false);
	let error = $state('');

	async function submit(event: SubmitEvent) {
		event.preventDefault();
		loading = true;
		error = '';
		const result = await api.createList({ name, description });
		loading = false;

		if (result.ok && result.data) {
			goto(`/lists/detail?id=${result.data.id}`);
		} else {
			error = result.message;
		}
	}
</script>

<div class="mx-auto max-w-2xl py-8">
	<h1 class="text-3xl font-bold text-gray-900">Create a mailing list</h1>
	<p class="mt-1 text-gray-600">You will receive all permissions for the new list.</p>

	<form
		class="mt-6 space-y-5 rounded-lg border border-gray-200 bg-white p-6 shadow-sm"
		onsubmit={submit}
	>
		<div>
			<label class="block text-sm font-medium text-gray-700" for="name">Name</label>
			<input
				id="name"
				required
				maxlength="100"
				bind:value={name}
				class="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 focus:border-blue-500 focus:outline-none"
			/>
		</div>
		<div>
			<label class="block text-sm font-medium text-gray-700" for="description">Description</label>
			<textarea
				id="description"
				required
				maxlength="300"
				rows="4"
				bind:value={description}
				class="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 focus:border-blue-500 focus:outline-none"
			></textarea>
		</div>
		<Feedback {error} />
		<div class="flex gap-3">
			<button
				type="submit"
				disabled={loading}
				class="rounded-md bg-blue-600 px-4 py-2 font-medium text-white hover:bg-blue-700 disabled:opacity-50"
			>
				{loading ? 'Creating…' : 'Create list'}
			</button>
			<a
				class="rounded-md border border-gray-300 px-4 py-2 text-gray-700 hover:bg-gray-50"
				href="/lists"
			>
				Cancel
			</a>
		</div>
	</form>
</div>
