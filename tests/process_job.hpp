#ifndef MEGOHTTP_TESTS_PROCESS_JOB_HPP_INCLUDED
#define MEGOHTTP_TESTS_PROCESS_JOB_HPP_INCLUDED

// Windows Job Object helper for test fixtures that spawn long-lived Python
// servers. The servers never exit on their own, so killing only the direct
// child (or cmd.exe) is not enough: a test timeout/crash skips fixture
// destructors and leaves the Python process behind. A job with
// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE ties the whole child tree to this test
// process: when the last job handle closes (normal stop, crash, or runner
// timeout), Windows terminates every process in the job.

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdlib>
#include <string>
#include <vector>

namespace mghttp_test {

    class ProcessJob {
    public:
        ProcessJob() {
            // Nested jobs are not safe in every host (containers/sandboxes put
            // the test process itself in a job). Assigning a child to a second
            // job there can make process teardown hang, so use the taskkill /T
            // fallback in that case instead.
            BOOL already_in_job = FALSE;
            if (IsProcessInJob(GetCurrentProcess(), nullptr, &already_in_job) &&
                already_in_job) {
                return;
            }
            SECURITY_ATTRIBUTES sa{};
            sa.nLength = sizeof sa;
            sa.bInheritHandle = FALSE;
            job_ = CreateJobObjectA(&sa, nullptr);
            if (!job_) return;
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if (!SetInformationJobObject(job_, JobObjectExtendedLimitInformation,
                                         &info, sizeof info)) {
                CloseHandle(job_);
                job_ = nullptr;
                return;
            }
            valid_ = true;
        }

        ~ProcessJob() { close(); }

        ProcessJob(const ProcessJob&) = delete;
        ProcessJob& operator=(const ProcessJob&) = delete;

        bool valid() const noexcept { return valid_; }
        bool assigned() const noexcept { return assigned_; }

        // Assign an already-created process (or one launched with
        // CREATE_SUSPENDED). Returns false when the environment forbids nested
        // jobs; callers then fall back to taskkill /T.
        bool assign(HANDLE process) noexcept {
            if (!valid_ || !process) return false;
            assigned_ = AssignProcessToJobObject(job_, process) != 0;
            return assigned_;
        }

        void terminate() noexcept {
            if (valid_) TerminateJobObject(job_, 0);
        }

        void close() noexcept {
            if (job_) {
                // KILL_ON_JOB_CLOSE makes this the final safety net even if a
                // test process exits without calling terminate().
                CloseHandle(job_);
                job_ = nullptr;
            }
            valid_ = false;
            assigned_ = false;
        }

    private:
        HANDLE job_{nullptr};
        bool valid_{false};
        bool assigned_{false};
    };

    // Starts a process and assigns it to the job. Job assignment failure is
    // reported through job.assigned(); callers must fall back to taskkill /T.
    // Nested jobs are skipped entirely when the test process already lives in
    // one (sandboxes/containers), because assigning there can hang teardown.
    inline bool spawn_in_job(const std::string& cmd, STARTUPINFOA& si,
                             DWORD creation_flags, PROCESS_INFORMATION& pi,
                             ProcessJob& job, BOOL inherit_handles = TRUE) {
        std::vector<char> mutable_cmd(cmd.begin(), cmd.end());
        mutable_cmd.push_back('\0');
        // Suspend only when a job will actually receive the process: that
        // closes the cmd.exe -> python.exe spawn window. If the host already
        // puts us in a job, no nested job is created and no suspend is needed.
        const DWORD flags = creation_flags |
                            (job.valid() ? CREATE_SUSPENDED : 0);
        const BOOL ok = CreateProcessA(
            nullptr, mutable_cmd.data(), nullptr, nullptr, inherit_handles,
            flags, nullptr, nullptr, &si, &pi);
        if (!ok) return false;
        if (job.valid()) {
            job.assign(pi.hProcess);
            ResumeThread(pi.hThread);
        }
        CloseHandle(pi.hThread);
        pi.hThread = nullptr;
        return true;
    }

    // Terminates the direct child spawned by spawn_in_job (the Python server).
    //
    // Deliberately NOT `taskkill /F /T`: on this host that command fast-fails
    // (0xC0000409, no output) when it runs after a DoH client + borrowed
    // executor have been torn down, which made test_resolver_doh crash at
    // fixture teardown in essentially every run (bisected: /T is the trigger;
    // /F without /T and TerminateProcess are both clean). Terminating the child
    // directly is also cheaper - no cmd.exe spawn per fixture.
    //
    // The fixtures start the Python interpreter directly, so there is no
    // grandchild that /T would have reached. Where a Job Object exists,
    // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE already kills the whole tree.
    inline void terminate_child(DWORD pid) {
        if (pid == 0) return;
        HANDLE process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
        if (!process) return;   // already gone, or not ours to kill
        TerminateProcess(process, 0);
        WaitForSingleObject(process, 5000);
        CloseHandle(process);
    }

} // namespace mghttp_test

#else

#include <string>

namespace mghttp_test {
    class ProcessJob {
    public:
        bool valid() const noexcept { return false; }
        bool assigned() const noexcept { return false; }
        bool assign(void*) noexcept { return false; }
        void terminate() noexcept {}
        void close() noexcept {}
    };
} // namespace mghttp_test

#endif // _WIN32

#endif // MEGOHTTP_TESTS_PROCESS_JOB_HPP_INCLUDED
